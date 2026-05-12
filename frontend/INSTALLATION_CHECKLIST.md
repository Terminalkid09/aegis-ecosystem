# AEGIS Dashboard - Installation & Verification Checklist

## Pre-Installation Requirements

- [ ] Node.js 14+ installed (`node --version`)
- [ ] npm installed (`npm --version`)
- [ ] aegis-brain running on `http://localhost:8000`
- [ ] Database populated with sample data
- [ ] Backend API responding to `/api/v1/stats`

## Installation Steps

### Step 1: Navigate to Frontend Directory
```bash
cd frontend
```
- [ ] Directory changed successfully
- [ ] Confirm location: `pwd` or `cd` and verify

### Step 2: Install Dependencies
```bash
npm install
```
- [ ] All packages installed (no errors)
- [ ] `node_modules/` directory created (~500+ MB)
- [ ] `package-lock.json` generated
- [ ] Installation completed in < 5 minutes

### Step 3: Setup Environment
```bash
cp .env.example .env
```
- [ ] `.env` file created
- [ ] `.env` contains `REACT_APP_API_URL=http://localhost:8000/api/v1`
- [ ] Edit `.env` if backend is on different port

### Step 4: Start Development Server
```bash
npm start
```
- [ ] Development server started
- [ ] Terminal shows: "Compiled successfully!"
- [ ] Browser opens to `http://localhost:3000`
- [ ] No console errors in terminal

## Verification Checklist

### UI Elements Visible

#### Sidebar
- [ ] Sidebar visible on left
- [ ] "AEGIS" logo with icon
- [ ] Menu items: Dashboard, Alerts, Agents, Settings
- [ ] Logout button at bottom
- [ ] Hover effects working on menu items

#### Top Bar
- [ ] "AEGIS EDR Dashboard" title visible
- [ ] Green "System Online" indicator
- [ ] Gradient background applied

#### Dashboard Page (Default)
- [ ] "Dashboard" header visible
- [ ] Threat Level indicator card
- [ ] 4 stat cards: Total Alerts, Unresolved Threats, Active Agents, Critical Threats
- [ ] Numbers displaying correctly
- [ ] Severity breakdown section with colored boxes
- [ ] All elements responsive

#### Alerts Page
- [ ] Click "Alerts" in sidebar
- [ ] Table with headers: Timestamp, Agent ID, Severity, Process Name, Event Type, Status, Action
- [ ] Rows populated with alert data (if data exists)
- [ ] Search box functional
- [ ] Severity filter dropdown working
- [ ] Status filter dropdown working
- [ ] Severity badges color-coded
- [ ] "Resolve" button present and clickable
- [ ] Pagination controls at bottom

#### Agents Page
- [ ] Click "Agents" in sidebar
- [ ] Search box visible
- [ ] Agent cards displayed in grid format
- [ ] Each card shows: Hostname, Agent ID, IP, OS, Last Seen
- [ ] Status badges (Active/Offline) visible
- [ ] "View Details" button present

#### Settings Page
- [ ] Click "Settings" in sidebar
- [ ] Toggle switches for: Notifications, Auto Refresh, Dark Mode, Sound Alerts
- [ ] API Configuration section
- [ ] Save Settings button
- [ ] About section with version info

### API Connectivity

#### Stats API
```bash
curl http://localhost:8000/api/v1/stats
```
- [ ] Returns 200 status
- [ ] Response has: total_alerts, unresolved_alerts, active_agents, critical_alerts
- [ ] Dashboard stats match API response

#### Alerts API
```bash
curl http://localhost:8000/api/v1/alerts
```
- [ ] Returns 200 status
- [ ] Response is array of alerts
- [ ] Each alert has: id, timestamp, severity, agent_id, process_name, is_resolved
- [ ] Alert table populates correctly

#### Agents API
```bash
curl http://localhost:8000/api/v1/agents
```
- [ ] Returns 200 status
- [ ] Response is array of agents
- [ ] Each agent has: agent_id, hostname, ip_address, os_type, last_seen
- [ ] Agents grid populates correctly

### Functionality Testing

#### Search & Filter (Alerts)
- [ ] Type in search box
- [ ] Results filter in real-time
- [ ] Filter by Severity (e.g., CRITICAL)
- [ ] Filter by Status (Resolved/Unresolved)
- [ ] Combination filters work together

#### Search (Agents)
- [ ] Type hostname/IP in search
- [ ] Results filter immediately
- [ ] Clear search shows all agents

#### Pagination (Alerts)
- [ ] Table shows 10 items per page (by default)
- [ ] Page numbers display at bottom
- [ ] Next/Previous buttons functional
- [ ] Page indicator updates correctly

#### Alert Resolution
- [ ] Click "Resolve" button on an alert
- [ ] Button shows "Resolving..." state
- [ ] Alert updates in table (status changes)
- [ ] Page auto-refreshes with new data

#### Severity Color Coding
- [ ] CRITICAL alerts = Red badge
- [ ] HIGH alerts = Orange badge
- [ ] MEDIUM alerts = Yellow badge
- [ ] LOW alerts = Blue badge

### Browser DevTools Checks

#### Console
```javascript
Open Browser DevTools (F12) → Console tab
```
- [ ] No JavaScript errors (red messages)
- [ ] No CORS errors
- [ ] No 404 errors in network requests
- [ ] API calls successful (status 200)

#### Network Tab
```javascript
Open DevTools → Network tab → Reload page
```
- [ ] GET /api/v1/stats - 200 status
- [ ] GET /api/v1/alerts - 200 status
- [ ] GET /api/v1/agents - 200 status
- [ ] Main app.js bundle loads
- [ ] CSS files load correctly
- [ ] No failed requests (4xx, 5xx)

#### Responsive Design
- [ ] Desktop (1920px+): All elements visible, 3-column grids
- [ ] Tablet (768px): 2-column grids adapt
- [ ] Resize browser: Elements reflow correctly

### Performance Checks

- [ ] Dashboard loads in < 3 seconds
- [ ] API responses < 1 second (if data exists)
- [ ] No console warnings about React
- [ ] Smooth animations/transitions
- [ ] No freezing when clicking buttons

### Browser Compatibility

- [ ] Chrome/Chromium ✓
- [ ] Firefox ✓
- [ ] Safari ✓
- [ ] Edge ✓

## Troubleshooting Guide

### Issue: "Cannot GET /"
**Solution**: 
- Ensure `npm start` is running
- Check terminal for errors
- Verify port 3000 is free

### Issue: API connection errors (404, 500)
**Solution**:
```bash
# Check backend is running
curl http://localhost:8000/api/v1/stats

# If fails, start aegis-brain:
cd aegis-brain
python main.py
```

### Issue: Styles not applied (no colors/layout)
**Solution**:
```bash
# Clear cache and restart
rm -rf node_modules/.cache
npm start
```

### Issue: "Module not found" errors
**Solution**:
```bash
# Reinstall dependencies
rm -rf node_modules
rm package-lock.json
npm install
npm start
```

### Issue: Port 3000 already in use
**Solution**:
```bash
# Kill process on port 3000
# Windows: netstat -ano | findstr :3000, then taskkill /PID <PID>
# Mac/Linux: lsof -ti:3000 | xargs kill -9

# Or use different port:
PORT=3001 npm start
```

## Performance Benchmarks

Target Metrics:
- [ ] Page load: < 3 seconds
- [ ] API response: < 500 ms
- [ ] UI render: < 100 ms
- [ ] Search response: < 200 ms
- [ ] Sort/filter: < 200 ms

Measure in DevTools:
1. Open DevTools → Performance tab
2. Click Record button
3. Perform action (load page, search, etc.)
4. Click Stop button
5. Check FPS and Main thread activity

## Documentation Verification

- [ ] README.md exists and is readable
- [ ] DEVELOPMENT.md covers setup and architecture
- [ ] ROADMAP.md lists future features
- [ ] BUILD_SUMMARY.md explains what was built
- [ ] .env.example provided as template

## Git Setup (Optional)

```bash
git add .
git commit -m "feat: Add AEGIS EDR Dashboard v1.0.0"
git push
```
- [ ] Changes committed
- [ ] No uncommitted files
- [ ] Branch is up to date

## Production Build (Optional)

```bash
npm run build
```
- [ ] Build completes successfully
- [ ] `build/` directory created
- [ ] No warnings in build output
- [ ] Bundle size reasonable (check with `npm run build -- --stats`)

## Final Sign-Off

### Development Environment
- [ ] npm install completed
- [ ] npm start runs without errors
- [ ] All UI elements visible
- [ ] API connectivity confirmed
- [ ] No console errors
- [ ] All pages accessible

### Functionality
- [ ] Dashboard displays stats
- [ ] Alerts table shows data
- [ ] Agents grid shows endpoints
- [ ] Search/filter working
- [ ] Alert resolution working
- [ ] Settings page functional

### Quality
- [ ] No console errors
- [ ] Responsive design working
- [ ] Loading states visible
- [ ] Error handling works
- [ ] Documentation complete

### Ready for:
- [ ] Local development
- [ ] Team collaboration
- [ ] Feature development
- [ ] Production deployment
- [ ] User testing

---

## Quick Command Reference

```bash
# Installation
cd frontend
npm install
npm start

# Development
npm start              # Start dev server
npm run build         # Build for production

# Cleanup
npm cache clean --force
rm -rf node_modules
rm package-lock.json

# Testing APIs
curl http://localhost:8000/api/v1/stats
curl http://localhost:8000/api/v1/alerts
curl http://localhost:8000/api/v1/agents

# Port management
lsof -ti:3000         # Find process on port 3000
kill -9 <PID>         # Kill process (Mac/Linux)
```

## Success! 🎉

If all checkboxes are checked, the AEGIS EDR Dashboard is:
✅ Properly installed
✅ Fully functional
✅ Connected to backend
✅ Ready for development
✅ Ready for deployment

Proceed with confidence! 🚀
