# AEGIS Dashboard - Development Guide

## Quick Start

### Prerequisites
- Node.js 16+ installed
- Backend services running:
  - `aegis-brain` (FastAPI) on port 8000
  - `aegis-link` (Spring Boot) on configured port

### Setup (5 minutes)

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Create environment file
cp .env.example .env

# Start development server
npm start
```

The dashboard will automatically open at `http://localhost:3000`.

## Architecture Overview

### Component Hierarchy

```
App (Main Router)
├── DashboardProvider (Context)
│   └── AppContent
│       ├── Sidebar (Navigation)
│       ├── Top Bar (Status)
│       └── Main Content (Dynamic)
│           ├── DashboardOverview
│           ├── AlertsTable
│           ├── AgentsList
│           └── Settings
```

### State Management Flow

```
DashboardContext
├── currentPage (string) - Current active page
├── setCurrentPage (function) - Navigate between pages
├── refreshTrigger (number) - Trigger data refresh
└── refreshData (function) - Increment refresh trigger

Components listen to refreshTrigger via useEffect
→ Components re-fetch data
→ UI updates with new data
```

### API Service Architecture

```
api.js (Axios Client)
├── apiClient (Base Instance)
│   ├── Interceptors (Error Handling)
│   └── Config (Headers, Timeout)
├── alertsAPI
│   ├── getAlerts(params)
│   ├── getAlert(id)
│   └── resolveAlert(id, resolved)
├── agentsAPI
│   └── getAgents(params)
└── statsAPI
    └── getStats()
```

## Component Details

### 1. Sidebar.js
**Purpose**: Navigation and branding
**State**: Uses `useDashboard()` context
**Features**:
- Menu items with icons
- Active state highlighting
- Responsive collapsible design
- Logout button

**Usage**:
```jsx
import Sidebar from './components/Sidebar';
// Wrap in DashboardProvider
```

### 2. DashboardOverview.js
**Purpose**: Display system statistics and threat level
**API Call**: `statsAPI.getStats()`
**State Management**:
- `stats` - Statistics data
- `loading` - Loading state
- `error` - Error handling
- `refreshTrigger` - Listen for refresh events

**Features**:
- Threat level calculation (Normal/Warning/Critical)
- 4 stat cards (Total, Unresolved, Active, Critical)
- Severity breakdown

### 3. AlertsTable.js
**Purpose**: Alert listing, filtering, and resolution
**API Calls**:
- `alertsAPI.getAlerts(params)` - Fetch alerts
- `alertsAPI.resolveAlert(id)` - Mark resolved

**Features**:
- Multi-column table with sorting
- Search across multiple fields
- Severity filtering
- Resolution status filtering
- Pagination (10 items/page)
- Severity color badges
- One-click resolution with loading state

**Filters**:
```javascript
{
  severity: 'CRITICAL|HIGH|MEDIUM|LOW',
  is_resolved: true|false,
  agent_id: 'search string',
  limit: 1000,
  offset: 0
}
```

### 4. AgentsList.js
**Purpose**: Monitor connected endpoints
**API Call**: `agentsAPI.getAgents(params)`
**Features**:
- Grid layout (3 columns on desktop)
- Active/Offline status detection
- OS-specific icons
- Human-readable "Last Seen" times
- Quick details button

**Active Detection Logic**:
```javascript
isActive = (now - lastSeen) < 10 minutes
```

### 5. Settings.js
**Purpose**: User preferences and configuration
**Features**:
- Toggle settings with UI switches
- API URL configuration
- LocalStorage persistence
- About information

## Styling System

### Tailwind CSS Integration

The project uses **Tailwind CSS 3** with custom configuration:

**Key Files**:
- `tailwind.config.js` - Theme customization
- `postcss.config.js` - PostCSS pipeline
- `src/styles/index.css` - Global styles

**Custom Utilities**:
```css
@tailwind base;        /* Reset & defaults */
@tailwind components;  /* Pre-made components */
@tailwind utilities;   /* Utility classes */

.btn-gradient { /* Custom gradient button */ }
.card { /* Card component base */ }
.input-base { /* Form input base */ }
.spinner { /* Loading spinner */ }
```

**Color Palette**:
```javascript
{
  slate: {    // Neutrals (backgrounds, text)
    950: '#030712',
    900: '#0f172a',
    800: '#1e293b',
    700: '#334155',
    400: '#94a3b8',
    300: '#cbd5e1'
  },
  cyan: {     // Accent (primary interactive)
    500: '#06b6d4',
    600: '#0891b2'
  },
  red:    // Severity: Critical
  orange: // Severity: High
  yellow: // Severity: Medium
  blue:   // Severity: Low
}
```

## API Integration Patterns

### Basic Fetch Pattern

```javascript
import { alertsAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';

export default function MyComponent() {
  const { refreshTrigger } = useDashboard();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchData();
  }, [refreshTrigger]);

  const fetchData = async () => {
    try {
      setLoading(true);
      const response = await alertsAPI.getAlerts({
        severity: 'CRITICAL',
        limit: 100
      });
      setData(response.data);
      setError(null);
    } catch (err) {
      setError('Failed to load data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Render based on state...
}
```

### Triggering Data Refresh

```javascript
import { useDashboard } from '../context/DashboardContext';

function MyComponent() {
  const { refreshData } = useDashboard();

  const handleResolve = async (id) => {
    await alertsAPI.resolveAlert(id);
    refreshData(); // Triggers re-fetch in all components
  };
}
```

## Performance Tips

1. **Pagination**: Large datasets are paginated (10 items/page)
2. **Debouncing**: Search input uses direct state updates (TODO: add debounce)
3. **Lazy Loading**: Tables load on demand
4. **Memoization**: Use dependency arrays correctly in useEffect
5. **CSS**: Use Tailwind utilities instead of custom CSS when possible

## Common Development Tasks

### Add a New Page

1. Create component in `src/components/NewPage.js`
2. Add route in `DashboardContext` or `App.js`
3. Add menu item in `Sidebar.js`
4. Export from component barrel file

```javascript
// src/components/index.js
export { default as Sidebar } from './Sidebar';
export { default as DashboardOverview } from './DashboardOverview';
// ... add new export
```

### Add a New API Endpoint

1. Add to `src/services/api.js`:
```javascript
export const newAPI = {
  getNewData: (params) => apiClient.get('/new-endpoint', { params }),
};
```

2. Import and use in component:
```javascript
import { newAPI } from '../services/api';
const response = await newAPI.getNewData({ param: 'value' });
```

### Modify Styling

1. **Global Styles**: Edit `src/styles/index.css`
2. **Tailwind Config**: Edit `tailwind.config.js` for theme changes
3. **Component Styles**: Use Tailwind classes directly in JSX

Example:
```jsx
<div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
  <h2 className="text-2xl font-bold text-cyan-400">Title</h2>
</div>
```

## Debugging

### Console Logging
```javascript
console.log('Alert ID:', alertId); // Simple log
console.table(data);               // Table format
console.error('Error:', error);    // Error level
```

### React DevTools
1. Install [React DevTools Chrome Extension](https://chrome.google.com/webstore/detail/react-developer-tools)
2. Open DevTools → Components tab
3. Inspect component tree and state

### Network Debugging
1. Open Chrome DevTools → Network tab
2. Filter to XHR requests
3. Check request/response payloads
4. Verify status codes (200, 400, 500, etc.)

### API Testing
```javascript
// In browser console, test API directly:
const { alertsAPI } = await import('./services/api.js');
alertsAPI.getAlerts().then(res => console.log(res.data));
```

## Troubleshooting Common Issues

### Issue: "Cannot find module 'lucide-react'"
```bash
npm install lucide-react
```

### Issue: Tailwind CSS not working
```bash
# Clear cache and restart
rm -rf node_modules/.cache
npm start
```

### Issue: CORS error when calling backend
- Ensure backend CORS settings allow localhost:3000
- Check `REACT_APP_API_URL` in `.env`
- Verify backend is actually running

### Issue: Styles look different than expected
- Check if `index.css` is imported in `index.js`
- Verify Tailwind build completed (check terminal output)
- Ensure `tailwind.config.js` includes correct paths

## Testing

### Running Tests
```bash
npm test
```

### Writing a Test
```javascript
import { render, screen } from '@testing-library/react';
import { DashboardProvider } from '../context/DashboardContext';
import Sidebar from '../components/Sidebar';

test('renders sidebar menu items', () => {
  render(
    <DashboardProvider>
      <Sidebar />
    </DashboardProvider>
  );
  expect(screen.getByText('Dashboard')).toBeInTheDocument();
});
```

## Production Build

### Build Optimization
```bash
npm run build
```

Creates optimized production build in `build/` directory with:
- Minified JavaScript
- Optimized CSS
- Source maps
- Asset hashing

### Deployment
```bash
# Build
npm run build

# Deploy build/ folder to web server
# Configure API URL via environment variables
```

## Resources

- [React Documentation](https://react.dev)
- [Tailwind CSS Docs](https://tailwindcss.com/docs)
- [Lucide Icons](https://lucide.dev)
- [Axios Documentation](https://axios-http.com)

## Contributing

1. Follow existing code style
2. Use functional components and hooks
3. Add PropTypes or TypeScript types
4. Test before committing
5. Update documentation for major changes

## Support

For issues:
1. Check this guide first
2. Review component source code
3. Check browser console errors
4. Test API with curl/Postman
5. Open an issue with reproduction steps
