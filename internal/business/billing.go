package business

import (
	"database/sql"
	"fmt"
	"time"

	"pqc-authenticator/internal/utils"
)

type Billing struct {
	db     *sql.DB
	logger utils.Logger
}

func NewBilling(db *sql.DB, logger utils.Logger) *Billing {
	return &Billing{
		db:     db,
		logger: logger,
	}
}

type PlanLimits struct {
	MaxUsers        int `json:"max_users"`
	MaxVerifications int `json:"max_verifications_per_month"`
	MaxIntegrations int `json:"max_integrations"`
}

type UsageInfo struct {
	CurrentUsers         int `json:"current_users"`
	VerificationsThisMonth int `json:"verifications_this_month"`
	CurrentIntegrations  int `json:"current_integrations"`
}

var planLimits = map[string]PlanLimits{
	"basic": {
		MaxUsers:        100,
		MaxVerifications: 10000,
		MaxIntegrations: 1,
	},
	"pro": {
		MaxUsers:        1000,
		MaxVerifications: 100000,
		MaxIntegrations: 5,
	},
	"enterprise": {
		MaxUsers:        -1, // unlimited
		MaxVerifications: -1, // unlimited
		MaxIntegrations: -1, // unlimited
	},
}

func (b *Billing) GetPlanLimits(plan string) PlanLimits {
	if limits, exists := planLimits[plan]; exists {
		return limits
	}
	return planLimits["basic"]
}

func (b *Billing) GetUsageInfo(businessID string) (*UsageInfo, error) {
	currentUsers, err := b.getCurrentUsers(businessID)
	if err != nil {
		return nil, err
	}

	verificationsThisMonth, err := b.getVerificationsThisMonth(businessID)
	if err != nil {
		return nil, err
	}

	currentIntegrations, err := b.getCurrentIntegrations(businessID)
	if err != nil {
		return nil, err
	}

	return &UsageInfo{
		CurrentUsers:         currentUsers,
		VerificationsThisMonth: verificationsThisMonth,
		CurrentIntegrations:  currentIntegrations,
	}, nil
}

func (b *Billing) CheckLimits(businessID, plan string) error {
	limits := b.GetPlanLimits(plan)
	usage, err := b.GetUsageInfo(businessID)
	if err != nil {
		return err
	}

	if limits.MaxUsers != -1 && usage.CurrentUsers >= limits.MaxUsers {
		return fmt.Errorf("user limit exceeded: %d/%d", usage.CurrentUsers, limits.MaxUsers)
	}

	if limits.MaxVerifications != -1 && usage.VerificationsThisMonth >= limits.MaxVerifications {
		return fmt.Errorf("verification limit exceeded: %d/%d", usage.VerificationsThisMonth, limits.MaxVerifications)
	}

	if limits.MaxIntegrations != -1 && usage.CurrentIntegrations >= limits.MaxIntegrations {
		return fmt.Errorf("integration limit exceeded: %d/%d", usage.CurrentIntegrations, limits.MaxIntegrations)
	}

	return nil
}

func (b *Billing) getCurrentUsers(businessID string) (int, error) {
	query := `SELECT COUNT(*) FROM business_users WHERE business_id = ? AND is_active = 1`
	var count int
	err := b.db.QueryRow(query, businessID).Scan(&count)
	return count, err
}

func (b *Billing) getVerificationsThisMonth(businessID string) (int, error) {
	startOfMonth := time.Now().Truncate(24 * time.Hour).AddDate(0, 0, -time.Now().Day()+1)
	
	query := `
		SELECT COUNT(*) 
		FROM audit_logs al 
		JOIN business_users bu ON al.user_id = bu.user_id 
		WHERE bu.business_id = ? AND al.action IN ('totp_verified', 'business_totp_verified') AND al.created_at >= ?
	`
	var count int
	err := b.db.QueryRow(query, businessID, startOfMonth).Scan(&count)
	return count, err
}

func (b *Billing) getCurrentIntegrations(businessID string) (int, error) {
	return 1, nil
}