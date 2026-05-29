# AEGIS EDR Dashboard

A professional, high-performance React dashboard for visualizing security alerts and managing monitored endpoints in the AEGIS Endpoint Detection and Response (EDR) ecosystem.

## Features

- **Real-Time Dashboard**: Live statistics and threat level indicators
- **Alert Management**: View, filter, and resolve detected threats
- **Agent Monitoring**: Track endpoint status and configuration
- **Dark Theme**: Cybersecurity-focused aesthetic with modern UI
- **Responsive Design**: Works seamlessly on desktop and tablet devices
- **Fast Performance**: Optimized rendering with React Hooks and Context API

## Tech Stack

- **Frontend Framework**: React 18 (Functional Components & Hooks)
- **Styling**: Tailwind CSS 3 with custom cybersecurity theme
- **Icons**: Lucide React
- **HTTP Client**: Axios
- **State Management**: React Context API
- **Build Tool**: Create React App

## Prerequisites

- Node.js 14+ and npm/yarn
- Running AEGIS backend services:
  - `aegis-brain` (FastAPI) on `http://localhost:8000`
  - `aegis-link` (Spring Boot) on the configured port

## Installation

1. **Install Dependencies**
   ```bash
   cd frontend
   npm install
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env if your backend runs on a different address
   ```

3. **Start Development Server**
   ```bash
   npm start
   ```
   The dashboard will open at `http://localhost:3000`

## Project Structure

```
src/
├── components/           # React components
│   ├── Sidebar.js       # Navigation sidebar
│   ├── DashboardOverview.js  # Main dashboard with stats
│   ├── AlertsTable.js   # Alerts management interface
│   ├── AgentsList.js    # Monitored endpoints
│   └── Settings.js      # Configuration page
├── context/             # State management
│   └── DashboardContext.js  # Global dashboard state
├── services/            # API communication
│   └── api.js          # Axios configuration & API methods
├── styles/              # Styling
│   └── index.css       # Tailwind CSS & custom styles
├── App.js              # Main app component
└── index.js            # React DOM entry point
```

## API Integration

The dashboard communicates with the AEGIS backend through these endpoints:

### Stats
- `GET /api/v1/telemetry/stats` - Fetch overall statistics and unresolved severity counts

### Alerts
- `GET /api/v1/telemetry/alerts` - List alerts with filtering
  - Query params: `severity`, `is_resolved`
- `PATCH /api/v1/telemetry/alerts/{id}/resolve` - Mark alert as resolved

### Agents
- `GET /api/v1/telemetry/agents` - List monitored endpoints
  - Query params: `limit`, `active_only`

### AI, VaultX, OSINT
- `POST /api/v1/ai/chat` - Authenticated AI assistant requests
- `GET/POST /api/v1/vault/notes` - Authenticated encrypted notes
- `DELETE /api/v1/vault/notes/{id}` - Delete an authenticated user's note
- `GET /api/v1/osint/ip/{ip}` - IP lookup
- `GET /api/v1/osint/domain/{domain}` - Domain lookup compatibility route
- `GET /api/v1/osint/history` - Recent OSINT queries

## Available Pages

### 1. Dashboard
- Real-time threat level indicator (Normal/Warning/Critical)
- Statistical cards: Total Alerts, Unresolved Threats, Active Agents, Critical Threats
- Severity breakdown chart

### 2. Alerts
- Filterable alert table with:
  - Timestamp, Agent ID, Severity badge, Process Name, Event Type
  - Search functionality across multiple fields
  - One-click alert resolution
  - Pagination support (10 items per page)

### 3. Agents
- Grid view of monitored endpoints showing:
  - Hostname and unique Agent ID
  - IP address
  - Operating System
  - Last seen timestamp with human-readable format
  - Active/Offline status indicator

### 4. Settings
- Toggle notifications, auto-refresh, dark mode, and sound alerts
- API configuration
- About information

## Styling Guide

### Color Scheme

| Severity | Color | HEX |
|----------|-------|-----|
| Critical | Red | #dc2626 |
| High | Orange | #ea580c |
| Medium | Yellow | #eab308 |
| Low | Blue | #3b82f6 |

### Theme

- **Background**: Slate-950 (#030712) - Deep space black
- **Cards**: Slate-900 (#0f172a) - Dark blue-gray
- **Accent**: Cyan-500 (#06b6d4) - Bright cyber blue
- **Text**: Slate-300 (#cbd5e1) - Light gray

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REACT_APP_API_URL` | `http://localhost:8000/api/v1` | Backend API endpoint |
| `REACT_APP_ENABLE_NOTIFICATIONS` | `true` | Enable desktop notifications |
| `REACT_APP_ENABLE_AUTO_REFRESH` | `true` | Auto-refresh data periodically |
| `REACT_APP_REFRESH_INTERVAL` | `30000` | Refresh interval in milliseconds |

## Development

### Running Tests
```bash
npm test
```

### Building for Production
```bash
npm run build
```
This creates an optimized production build in the `build/` directory.

### Code Quality

The project uses functional components and React Hooks best practices:
- `useState` for component state
- `useEffect` for side effects and API calls
- `useContext` for global state management
- Custom context hooks for type-safe state access

## Performance Optimizations

- Lazy loading of table data with pagination
- Memoized API calls using dependency arrays
- Efficient re-renders with proper key usage
- CSS-based animations for smooth performance
- Responsive grid layouts

## Troubleshooting

### API Connection Error
- Verify backend is running: `http://localhost:8000/api/v1/stats`
- Check `.env` file for correct `REACT_APP_API_URL`
- Review browser console for CORS issues

### Styling Issues
- Ensure Tailwind CSS is properly installed
- Clear React dev server cache: `rm -rf node_modules/.cache`
- Restart development server: `npm start`

### No Data Displaying
- Check backend database connection
- Verify sample data exists in backend
- Check API responses in browser DevTools Network tab

## Contributing

1. Create a feature branch
2. Make your changes
3. Test thoroughly
4. Submit a pull request

## License

Part of the AEGIS EDR Ecosystem

## Support

For issues or questions:
1. Check existing documentation
2. Review browser console for error messages
3. Check backend logs for API errors
4. Open an issue with detailed reproduction steps
