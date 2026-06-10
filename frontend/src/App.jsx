import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import Container from '@mui/material/Container';
import Box from '@mui/material/Box';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import TimelineIcon from '@mui/icons-material/Timeline';

// Import Pages
import UploadPage from './pages/UploadPage';
import AnalysisPage from './pages/AnalysisPage';

// Theme configuration - clean light theme
const lightTheme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#2563eb', // Slate blue
    },
    secondary: {
      main: '#475569',
    },
    background: {
      default: '#f8fafc',
      paper: '#ffffff',
    },
    divider: '#e2e8f0',
  },
  typography: {
    fontFamily: '"Inter", "Outfit", sans-serif',
    h5: {
      fontFamily: 'Outfit, sans-serif',
      fontWeight: 600,
    },
    h6: {
      fontFamily: 'Outfit, sans-serif',
      fontWeight: 600,
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={lightTheme}>
      <CssBaseline />
      <Router>
        <AppBar position="static" elevation={0} sx={{ borderBottom: '1px solid', borderColor: 'divider', bgcolor: 'background.paper', color: 'text.primary' }}>
          <Toolbar>
            <TimelineIcon sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6" component="div" sx={{ flexGrow: 1, fontWeight: '700', letterSpacing: '-0.5px' }}>
              Vansh's <span style={{ color: '#2563eb', fontWeight: '400' }}>Log Analyser</span>
            </Typography>
            <Button
              component={Link}
              to="/upload"
              startIcon={<CloudUploadIcon />}
              sx={{ mr: 1, fontWeight: 500 }}
            >
              Upload Logs
            </Button>
            <Button
              component={Link}
              to="/analysis"
              startIcon={<TimelineIcon />}
              sx={{ fontWeight: 500 }}
            >
              Flow Analysis
            </Button>
          </Toolbar>
        </AppBar>

        <Box sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
          <Routes>
            <Route path="/" element={<Navigate to="/upload" replace />} />
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/analysis" element={<AnalysisPage />} />
          </Routes>
        </Box>
      </Router>
    </ThemeProvider>
  );
}

export default App;
