# PQC Authenticator Frontend

A modern React frontend for the PQC Authenticator system with post-quantum cryptographic TOTP authentication.

## Features

- **Modern UI**: Built with React and Tailwind CSS
- **Authentication**: Login/Register with JWT tokens
- **TOTP Management**: Create, manage, and generate TOTP codes
- **QR Code Generation**: Setup authenticator apps easily
- **Business API**: Enterprise integration demo
- **System Monitoring**: Real-time health and metrics
- **Responsive Design**: Works on desktop and mobile

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build
```

## Environment Variables

Create a `.env` file in the frontend directory:

```env
REACT_APP_API_URL=http://localhost:8443
```

## Project Structure

```
src/
├── components/          # Reusable UI components
│   └── Layout.js       # Main layout wrapper
├── contexts/           # React contexts
│   └── AuthContext.js  # Authentication state
├── pages/              # Page components
│   ├── Dashboard.js    # Main dashboard
│   ├── Login.js        # Login page
│   ├── Register.js     # Registration page
│   ├── TOTPManagement.js # TOTP account management
│   ├── BusinessAPI.js  # Business API demo
│   └── SystemStatus.js # System monitoring
├── services/           # API services
│   └── api.js         # Axios configuration
├── App.js             # Main app component
├── index.js           # Entry point
└── index.css          # Global styles
```

## Available Scripts

- `npm start` - Start development server
- `npm build` - Build for production
- `npm test` - Run tests
- `npm eject` - Eject from Create React App

## API Integration

The frontend connects to the PQC Authenticator backend running on port 8443. Make sure the backend is running before starting the frontend.

## Deployment

1. Build the production version:
   ```bash
   npm run build
   ```

2. Serve the build folder with any static server or deploy to:
   - Netlify
   - Vercel
   - AWS S3 + CloudFront
   - Nginx/Apache

## Development

The app uses hot reloading for development. Changes to files will automatically reload the browser.

### Key Dependencies

- **React 18**: Modern React with hooks
- **React Router**: Client-side routing
- **Tailwind CSS**: Utility-first CSS framework
- **Heroicons**: Beautiful SVG icons
- **Axios**: HTTP client for API calls
- **React Toastify**: Toast notifications
- **QRCode**: QR code generation

## Browser Support

- Chrome/Edge 88+
- Firefox 85+
- Safari 14+
- Mobile browsers with ES6 support