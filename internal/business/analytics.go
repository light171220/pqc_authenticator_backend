package business

import (
	"database/sql"
	"time"

	"pqc-authenticator/internal/utils"
)

type Analytics struct {
	db     *sql.DB
	logger utils.Logger
}

func NewAnalytics(db *sql.DB, logger utils.Logger) *Analytics {
	return &Analytics{
		db:     db,
		logger: logger,
	}
}

type DashboardData struct {
	TotalUsers        int                    `json:"total_users"`
	ActiveUsers       int                    `json:"active_users"`
	TotalVerifications int                   `json:"total_verifications"`
	SuccessRate       float64               `json:"success_rate"`
	RecentActivity    []ActivityItem        `json:"recent_activity"`
	UsageStats        map[string]interface{} `json:"usage_stats"`
}

type ActivityItem struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	UserID    string    `json:"user_id"`
	Success   bool      `json:"success"`
}

type AnalyticsData struct {
	TimeRange      string                 `json:"time_range"`
	TotalRequests  int                    `json:"total_requests"`
	SuccessRate    float64               `json:"success_rate"`
	DailyStats     []DailyStats          `json:"daily_stats"`
	UserStats      map[string]interface{} `json:"user_stats"`
	ErrorStats     map[string]int        `json:"error_stats"`
}

type DailyStats struct {
	Date         string  `json:"date"`
	Requests     int     `json:"requests"`
	Successes    int     `json:"successes"`
	SuccessRate  float64 `json:"success_rate"`
}

func (a *Analytics) GetDashboardData(businessID string) (*DashboardData, error) {
	totalUsers, err := a.getTotalUsers(businessID)
	if err != nil {
		return nil, err
	}

	activeUsers, err := a.getActiveUsers(businessID)
	if err != nil {
		return nil, err
	}

	totalVerifications, err := a.getTotalVerifications(businessID)
	if err != nil {
		return nil, err
	}

	successRate, err := a.getSuccessRate(businessID)
	if err != nil {
		return nil, err
	}

	recentActivity, err := a.getRecentActivity(businessID)
	if err != nil {
		return nil, err
	}

	usageStats, err := a.getUsageStats(businessID)
	if err != nil {
		return nil, err
	}

	return &DashboardData{
		TotalUsers:        totalUsers,
		ActiveUsers:       activeUsers,
		TotalVerifications: totalVerifications,
		SuccessRate:       successRate,
		RecentActivity:    recentActivity,
		UsageStats:        usageStats,
	}, nil
}

func (a *Analytics) GetAnalytics(businessID string, days int) (*AnalyticsData, error) {
	startDate := time.Now().AddDate(0, 0, -days)

	totalRequests, err := a.getTotalRequestsInPeriod(businessID, startDate)
	if err != nil {
		return nil, err
	}

	successRate, err := a.getSuccessRateInPeriod(businessID, startDate)
	if err != nil {
		return nil, err
	}

	dailyStats, err := a.getDailyStats(businessID, startDate, days)
	if err != nil {
		return nil, err
	}

	userStats, err := a.getUserStatsInPeriod(businessID, startDate)
	if err != nil {
		return nil, err
	}

	errorStats, err := a.getErrorStatsInPeriod(businessID, startDate)
	if err != nil {
		return nil, err
	}

	return &AnalyticsData{
		TimeRange:     formatTimeRange(days),
		TotalRequests: totalRequests,
		SuccessRate:   successRate,
		DailyStats:    dailyStats,
		UserStats:     userStats,
		ErrorStats:    errorStats,
	}, nil
}

func (a *Analytics) getTotalUsers(businessID string) (int, error) {
	query := `SELECT COUNT(*) FROM business_users WHERE business_id = ? AND is_active = 1`
	var count int
	err := a.db.QueryRow(query, businessID).Scan(&count)
	return count, err
}

func (a *Analytics) getActiveUsers(businessID string) (int, error) {
	query := `
		SELECT COUNT(DISTINCT al.user_id) 
		FROM audit_logs al 
		JOIN business_users bu ON al.user_id = bu.user_id 
		WHERE bu.business_id = ? AND al.created_at >= datetime('now', '-30 days')
	`
	var count int
	err := a.db.QueryRow(query, businessID).Scan(&count)
	return count, err
}

func (a *Analytics) getTotalVerifications(businessID string) (int, error) {
	query := `
		SELECT COUNT(*) 
		FROM audit_logs al 
		JOIN business_users bu ON al.user_id = bu.user_id 
		WHERE bu.business_id = ? AND al.action IN ('totp_verified', 'business_totp_verified')
	`
	var count int
	err := a.db.QueryRow(query, businessID).Scan(&count)
	return count, err
}

func (a *Analytics) getSuccessRate(businessID string) (float64, error) {
	query := `
		SELECT 
			COUNT(CASE WHEN json_extract(al.details, '$.result') = 'success' THEN 1 END) * 100.0 / COUNT(*) as success_rate
		FROM audit_logs al 
		JOIN business_users bu ON al.user_id = bu.user_id 
		WHERE bu.business_id = ? AND al.action IN ('totp_verified', 'business_totp_verified')
	`
	var rate float64
	err := a.db.QueryRow(query, businessID).Scan(&rate)
	return rate, err
}

func (a *Analytics) getRecentActivity(businessID string) ([]ActivityItem, error) {
	query := `
		SELECT al.created_at, al.action, al.user_id,
			CASE WHEN json_extract(al.details, '$.result') = 'success' THEN 1 ELSE 0 END as success
		FROM audit_logs al 
		JOIN business_users bu ON al.user_id = bu.user_id 
		WHERE bu.business_id = ? 
		ORDER BY al.created_at DESC 
		LIMIT 50
	`
	
	rows, err := a.db.Query(query, businessID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var activities []ActivityItem
	for rows.Next() {
		var activity ActivityItem
		var success int
		err := rows.Scan(&activity.Timestamp, &activity.Action, &activity.UserID, &success)
		if err != nil {
			return nil, err
		}
		activity.Success = success == 1
		activities = append(activities, activity)
	}
	return activities, nil
}

func (a *Analytics) getUsageStats(businessID string) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	query := `
		SELECT al.action, COUNT(*) as count
		FROM audit_logs al 
		JOIN business_users bu ON al.user_id = bu.user_id 
		WHERE bu.business_id = ? AND al.created_at >= datetime('now', '-30 days')
		GROUP BY al.action
	`
	
	rows, err := a.db.Query(query, businessID)
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	actionCounts := make(map[string]int)
	for rows.Next() {
		var action string
		var count int
		err := rows.Scan(&action, &count)
		if err != nil {
			return stats, err
		}
		actionCounts[action] = count
	}
	
	stats["action_counts"] = actionCounts
	return stats, nil
}

func (a *Analytics) getTotalRequestsInPeriod(businessID string, startDate time.Time) (int, error) {
	query := `
		SELECT COUNT(*) 
		FROM audit_logs al 
		JOIN business_users bu ON al.user_id = bu.user_id 
		WHERE bu.business_id = ? AND al.created_at >= ?
	`
	var count int
	err := a.db.QueryRow(query, businessID, startDate).Scan(&count)
	return count, err
}

func (a *Analytics) getSuccessRateInPeriod(businessID string, startDate time.Time) (float64, error) {
	query := `
		SELECT 
			COUNT(CASE WHEN json_extract(al.details, '$.result') = 'success' THEN 1 END) * 100.0 / COUNT(*) as success_rate
		FROM audit_logs al 
		JOIN business_users bu ON al.user_id = bu.user_id 
		WHERE bu.business_id = ? AND al.action IN ('totp_verified', 'business_totp_verified') AND al.created_at >= ?
	`
	var rate float64
	err := a.db.QueryRow(query, businessID, startDate).Scan(&rate)
	return rate, err
}

func (a *Analytics) getDailyStats(businessID string, startDate time.Time, days int) ([]DailyStats, error) {
	query := `
		SELECT 
			date(al.created_at) as date,
			COUNT(*) as requests,
			COUNT(CASE WHEN json_extract(al.details, '$.result') = 'success' THEN 1 END) as successes
		FROM audit_logs al 
		JOIN business_users bu ON al.user_id = bu.user_id 
		WHERE bu.business_id = ? AND al.action IN ('totp_verified', 'business_totp_verified') AND al.created_at >= ?
		GROUP BY date(al.created_at)
		ORDER BY date(al.created_at)
	`
	
	rows, err := a.db.Query(query, businessID, startDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []DailyStats
	for rows.Next() {
		var stat DailyStats
		var successes int
		err := rows.Scan(&stat.Date, &stat.Requests, &successes)
		if err != nil {
			return nil, err
		}
		stat.Successes = successes
		if stat.Requests > 0 {
			stat.SuccessRate = float64(successes) / float64(stat.Requests) * 100
		}
		stats = append(stats, stat)
	}
	return stats, nil
}

func (a *Analytics) getUserStatsInPeriod(businessID string, startDate time.Time) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	query := `
		SELECT COUNT(DISTINCT al.user_id) as unique_users
		FROM audit_logs al 
		JOIN business_users bu ON al.user_id = bu.user_id 
		WHERE bu.business_id = ? AND al.created_at >= ?
	`
	
	var uniqueUsers int
	err := a.db.QueryRow(query, businessID, startDate).Scan(&uniqueUsers)
	if err != nil {
		return stats, err
	}
	
	stats["unique_users"] = uniqueUsers
	return stats, nil
}

func (a *Analytics) getErrorStatsInPeriod(businessID string, startDate time.Time) (map[string]int, error) {
	errorStats := make(map[string]int)
	
	query := `
		SELECT al.action, COUNT(*) as count
		FROM audit_logs al 
		JOIN business_users bu ON al.user_id = bu.user_id 
		WHERE bu.business_id = ? AND al.created_at >= ? AND json_extract(al.details, '$.result') = 'failed'
		GROUP BY al.action
	`
	
	rows, err := a.db.Query(query, businessID, startDate)
	if err != nil {
		return errorStats, err
	}
	defer rows.Close()

	for rows.Next() {
		var action string
		var count int
		err := rows.Scan(&action, &count)
		if err != nil {
			return errorStats, err
		}
		errorStats[action] = count
	}
	
	return errorStats, nil
}

func formatTimeRange(days int) string {
	if days == 1 {
		return "Last 24 hours"
	} else if days <= 7 {
		return "Last week"
	} else if days <= 30 {
		return "Last month"
	} else if days <= 90 {
		return "Last 3 months"
	}
	return "Custom range"
}