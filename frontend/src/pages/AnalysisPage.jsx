import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import {
  Container,
  Box,
  Typography,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
  Grid,
  Drawer,
  IconButton,
  Chip,
  List,
  ListItem,
  ListItemText,
  Divider,
  Paper,
  TextField,
  Tooltip,
  Autocomplete
} from '@mui/material';
import FilterListIcon from '@mui/icons-material/FilterList';
import CloseIcon from '@mui/icons-material/Close';
import ShieldIcon from '@mui/icons-material/Shield';
import RefreshIcon from '@mui/icons-material/Refresh';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import TerminalIcon from '@mui/icons-material/Terminal';
import InfoIcon from '@mui/icons-material/Info';

const API_URL = 'http://localhost:8000';

// HSL tailored high-fidelity colors matching Wireshark protocol style
const PROTOCOL_THEMES = {
  "Authentication": {
    bg: "#eff6ff",     // soft blue
    border: "#bfdbfe",
    stroke: "#2563eb",
    text: "#1e3a8a",
    tag: "AUTH"
  },
  "DNS": {
    bg: "#f0fdf4",     // soft green
    border: "#bbf7d0",
    stroke: "#16a34a",
    text: "#14532d",
    tag: "DNS"
  },
  "Reconnaissance": {
    bg: "#fff7ed",     // soft orange
    border: "#fed7aa",
    stroke: "#ea580c",
    text: "#7c2d12",
    tag: "RECON"
  },
  "Malware": {
    bg: "#fff1f2",     // soft rose
    border: "#fecdd3",
    stroke: "#e11d48",
    text: "#881337",
    tag: "MALWARE"
  },
  "Network": {
    bg: "#faf5ff",     // soft purple
    border: "#e9d5ff",
    stroke: "#9333ea",
    text: "#581c87",
    tag: "NET"
  },
  "System": {
    bg: "#f8fafc",     // soft slate
    border: "#e2e8f0",
    stroke: "#475569",
    text: "#0f172a",
    tag: "SYS"
  },
  "Other": {
    bg: "#f8fafc",
    border: "#e2e8f0",
    stroke: "#64748b",
    text: "#334155",
    tag: "OTHER"
  }
};

function AnalysisPage() {
  const [logs, setLogs] = useState([]);
  const [uploads, setUploads] = useState([]);
  
  // Filtering States
  const [visualizeBy, setVisualizeBy] = useState('IP Address');
  const [selectedEntities, setSelectedEntities] = useState([]);
  const [eventCategory, setEventCategory] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');
  
  // Details Drawer & Loading States
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleClearDatabase = async () => {
    if (!window.confirm("Are you sure you want to delete all uploaded logs and incidents? This cannot be undone.")) {
      return;
    }
    setLoading(true);
    try {
      await axios.post(`${API_URL}/upload/clear`);
      setLogs([]);
      setSelectedEntities([]);
      setStartTime('');
      setEndTime('');
    } catch (err) {
      console.error("Failed to clear database:", err);
    } finally {
      setLoading(false);
    }
  };

  // Load uploads once
  useEffect(() => {
    const fetchUploads = async () => {
      try {
        const response = await axios.get(`${API_URL}/uploads`);
        setUploads(response.data);
      } catch (err) {
        console.error("Failed to load uploads for filter:", err);
      }
    };
    fetchUploads();
  }, []);

  // Fetch filtered data
  const generateVisualization = async () => {
    setLoading(true);
    try {
      const params = {};
      if (eventCategory !== 'all') params.event_category = eventCategory;
      if (severity !== 'all') params.severity = severity;
      if (startTime) params.start_time = startTime;
      if (endTime) params.end_time = endTime;
      
      // Pass the selected visualization criteria
      params.entity_type = visualizeBy;
      if (selectedEntities.length > 0) {
        params.entity_vals = selectedEntities.join(',');
      }

      const response = await axios.get(`${API_URL}/logs/flow`, { params });
      setLogs(response.data);
    } catch (err) {
      console.error("Failed to query flow logs:", err);
    } finally {
      setLoading(false);
    }
  };

  // Run query on load and when fundamental selections change
  useEffect(() => {
    generateVisualization();
  }, [visualizeBy]);

  // Reset selected entities when visualization criteria changes
  useEffect(() => {
    setSelectedEntities([]);
  }, [visualizeBy]);

  // Helper to resolve entity values from a log based on current visualization type
  const getEntityValue = (log, type) => {
    switch (type) {
      case 'IP Address':
        return [log.src_ip, log.dst_ip].filter(Boolean);
      case 'Username':
        return [log.src_user || log.dst_user, log.src_hostname || log.dst_hostname || log.dst_ip].filter(Boolean);
      case 'Hostname':
        return [log.src_hostname || log.dst_hostname, log.dst_ip || log.src_ip].filter(Boolean);
      case 'Protocol':
        return [log.protocol, log.application].filter(Boolean);
      case 'Application':
        return [log.application, log.process_name || log.protocol].filter(Boolean);
      default:
        return [log.src_ip, log.dst_ip].filter(Boolean);
    }
  };

  // Compute all unique entities available in the CURRENT loaded logs
  const allUniqueEntities = useMemo(() => {
    const set = new Set();
    logs.forEach(log => {
      getEntityValue(log, visualizeBy).forEach(val => set.add(val));
    });
    return Array.from(set).sort();
  }, [logs, visualizeBy]);



  // Determine the active lifelines (columns) to display in the graph
  const activeEntities = useMemo(() => {
    const counts = {};
    logs.forEach(log => {
      getEntityValue(log, visualizeBy).forEach(val => {
        counts[val] = (counts[val] || 0) + 1;
      });
    });

    if (selectedEntities.length > 0) {
      const selectedSet = new Set(selectedEntities.map(v => String(v).trim()));
      const partnerSet = new Set();
      
      logs.forEach(log => {
        const vals = getEntityValue(log, visualizeBy);
        const hasSelected = vals.some(val => selectedSet.has(val));
        if (hasSelected) {
          vals.forEach(val => {
            if (!selectedSet.has(val)) {
              partnerSet.add(val);
            }
          });
        }
      });
      
      const sortedPartners = Array.from(partnerSet).sort((a, b) => (counts[b] || 0) - (counts[a] || 0));
      const maxLanes = 30; // reasonable limit for visualization
      const combined = [
        ...selectedEntities,
        ...sortedPartners.slice(0, maxLanes)
      ];
      
      return Array.from(new Set(combined)).sort();
    }

    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(entry => entry[0])
      .sort();
  }, [logs, visualizeBy, selectedEntities]);

  // Helper to fetch mitigation playbook
  const getPlaybook = (category, name) => {
    if (category === "Authentication") {
      return [
        "Isolate account session and enforce password rotation.",
        "Verify geographical access details and source location.",
        "Audit log history for concurrent logins across IP addresses."
      ];
    }
    if (category === "Reconnaissance" || (name && name.toLowerCase().includes("scan"))) {
      return [
        "Temporarily block source IP address at perimeter gateway.",
        "Check firewall policy rules on targeted destination ports.",
        "Ensure host defense systems are actively dropping scan packets."
      ];
    }
    if (category === "Malware" || (name && name.toLowerCase().includes("malware"))) {
      return [
        "Quarantine system endpoint immediately to avoid lateral infection.",
        "Revoke all user token credentials logged in to host.",
        "Execute deep anti-malware system scans on host filesystem."
      ];
    }
    return [
      "Review raw payload contents inside original logs folder.",
      "Check connection thresholds and log protocol standards."
    ];
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 64px)', overflow: 'hidden', bgcolor: '#f8fafc' }}>
      {/* Premium Filtering Panel */}
      <Paper 
        variant="outlined" 
        sx={{ 
          p: 2.5, 
          m: 2, 
          mb: 0, 
          borderRadius: 4, 
          borderColor: '#e2e8f0', 
          background: 'rgba(255, 255, 255, 0.9)',
          backdropFilter: 'blur(8px)',
          boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.02), 0 2px 4px -2px rgb(0 0 0 / 0.02)'
        }}
      >
        <Grid container spacing={2.5} alignItems="center">
          {/* Row 1: Visualize By & Autocomplete */}
          <Grid item xs={12}>
            <Box sx={{ display: 'flex', gap: 2.5, alignItems: 'flex-start', flexWrap: 'wrap' }}>
              <FormControl size="small" sx={{ width: 200, flexShrink: 0 }}>
                <InputLabel sx={{ fontWeight: 500 }}>Visualize By</InputLabel>
                <Select
                  value={visualizeBy}
                  label="Visualize By"
                  onChange={(e) => setVisualizeBy(e.target.value)}
                  sx={{ borderRadius: 2 }}
                >
                  <MenuItem value="IP Address">IP Address</MenuItem>
                  <MenuItem value="Username">Username</MenuItem>
                  <MenuItem value="Hostname">Hostname</MenuItem>
                  <MenuItem value="Protocol">Protocol</MenuItem>
                  <MenuItem value="Application">Application</MenuItem>
                </Select>
              </FormControl>

              <Autocomplete
                multiple
                freeSolo
                size="small"
                options={allUniqueEntities}
                value={selectedEntities}
                onChange={(event, newValue) => {
                  setSelectedEntities(newValue);
                }}
                slotProps={{
                  listbox: {
                    style: { maxHeight: 250 }
                  }
                }}
                sx={{
                  minWidth: 400,
                  flexGrow: 1
                }}
                renderInput={(params) => (
                  <TextField
                    {...params}
                    fullWidth
                    label={`Select or Type ${visualizeBy}`}
                    placeholder={`Type ${visualizeBy} and press Enter...`}
                    sx={{ '& .MuiOutlinedInput-root': { borderRadius: 2 } }}
                  />
                )}
              />
            </Box>
          </Grid>

          {/* Row 2: 12 Columns Total */}
          <Grid item xs={12} sm={6} md={2}>
            <FormControl fullWidth size="small">
              <InputLabel sx={{ fontWeight: 500 }}>Event Category</InputLabel>
              <Select
                value={eventCategory}
                label="Event Category"
                onChange={(e) => setEventCategory(e.target.value)}
                sx={{ borderRadius: 2 }}
              >
                <MenuItem value="all">All Categories</MenuItem>
                <MenuItem value="Authentication">Authentication</MenuItem>
                <MenuItem value="DNS">DNS</MenuItem>
                <MenuItem value="Reconnaissance">Reconnaissance</MenuItem>
                <MenuItem value="Malware">Malware</MenuItem>
                <MenuItem value="System">System</MenuItem>
                <MenuItem value="Network">Network</MenuItem>
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} sm={6} md={2}>
            <FormControl fullWidth size="small">
              <InputLabel sx={{ fontWeight: 500 }}>Severity</InputLabel>
              <Select
                value={severity}
                label="Severity"
                onChange={(e) => setSeverity(e.target.value)}
                sx={{ borderRadius: 2 }}
              >
                <MenuItem value="all">All Levels</MenuItem>
                <MenuItem value="Low">Low</MenuItem>
                <MenuItem value="Medium">Medium</MenuItem>
                <MenuItem value="High">High</MenuItem>
                <MenuItem value="Critical">Critical</MenuItem>
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={6} sm={4} md={2}>
            <TextField
              size="small"
              fullWidth
              label="Start Time"
              placeholder="HH:MM:SS"
              value={startTime}
              onChange={(e) => setStartTime(e.target.value)}
              slotProps={{ inputLabel: { shrink: true } }}
              sx={{ '& .MuiOutlinedInput-root': { borderRadius: 2 } }}
            />
          </Grid>

          <Grid item xs={6} sm={4} md={2}>
            <TextField
              size="small"
              fullWidth
              label="End Time"
              placeholder="HH:MM:SS"
              value={endTime}
              onChange={(e) => setEndTime(e.target.value)}
              slotProps={{ inputLabel: { shrink: true } }}
              sx={{ '& .MuiOutlinedInput-root': { borderRadius: 2 } }}
            />
          </Grid>

          <Grid item xs={12} sm={12} md={4} sx={{ display: 'flex', gap: 1.2, justifyContent: 'flex-end', alignItems: 'center' }}>
            {logs.length > 0 && (
              <Button
                variant="outlined"
                color="error"
                size="medium"
                onClick={handleClearDatabase}
                sx={{ borderRadius: 2.5, textTransform: 'none', px: 2, fontWeight: 600, height: 40, minWidth: 'fit-content' }}
              >
                Clear
              </Button>
            )}
            <Button
              variant="outlined"
              size="medium"
              onClick={() => {
                setSelectedEntities([]);
                setEventCategory('all');
                setSeverity('all');
                setStartTime('');
                setEndTime('');
              }}
              sx={{ borderRadius: 2.5, textTransform: 'none', px: 2.5, fontWeight: 600, height: 40 }}
            >
              Reset
            </Button>
            <Button
              variant="contained"
              size="medium"
              startIcon={<FilterListIcon />}
              onClick={generateVisualization}
              disabled={loading}
              sx={{ borderRadius: 2.5, textTransform: 'none', px: 3, fontWeight: 600, height: 40, boxShadow: 'none', '&:hover': { boxShadow: 'none' } }}
            >
              Apply Filter
            </Button>
          </Grid>
        </Grid>
      </Paper>

      {/* Info helper tag */}
      <Box sx={{ px: 3, pt: 1, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="caption" color="text.secondary" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <InfoIcon sx={{ fontSize: 13 }} />
          Showing {logs.filter(log => {
            if (activeEntities.length === 0) return true;
            const vals = getEntityValue(log, visualizeBy);
            return vals.length > 0 && vals.every(v => activeEntities.includes(v));
          }).length.toLocaleString()} log entries. Active Lifelines: {activeEntities.join(', ') || 'None (aggregating top active columns)'}.
        </Typography>
      </Box>

      {/* Main Wireshark Sequence Diagram Visualizer Container */}
      <Box sx={{ flexGrow: 1, m: 2, mt: 0.5, border: '1px solid #cbd5e1', borderRadius: 4, bgcolor: '#ffffff', overflow: 'hidden', display: 'flex', flexDirection: 'column', boxShadow: '0 10px 15px -3px rgb(0 0 0 / 0.05)' }}>
        {logs.length === 0 ? (
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 1.5 }}>
            <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 600 }}>
              No Event Records Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Upload log sources or adjust filters to populate the flow graph.
            </Typography>
          </Box>
        ) : (
          /* Scrollable Wireshark Container */
          <Box sx={{ overflow: 'auto', flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
            <Box sx={{ minWidth: 120 + activeEntities.length * 200 + 400, display: 'flex', flexDirection: 'column', flexGrow: 1 }}>
              
              {/* Sticky Columns Header */}
              <Box 
                sx={{ 
                  position: 'sticky', 
                  top: 0, 
                  zIndex: 20, 
                  display: 'flex', 
                  height: 52, 
                  background: 'linear-gradient(180deg, #f8fafc, #f1f5f9)', 
                  borderBottom: '2px solid #cbd5e1',
                  boxShadow: '0 2px 4px rgba(0,0,0,0.02)'
                }}
              >
                {/* 1. Time Column Header */}
                <Box 
                  sx={{ 
                    width: 120, 
                    minWidth: 120, 
                    display: 'flex', 
                    alignItems: 'center', 
                    justifyContent: 'center', 
                    fontWeight: 700, 
                    fontSize: '11px', 
                    color: '#475569', 
                    borderRight: '1px solid #cbd5e1',
                    textTransform: 'uppercase',
                    letterSpacing: '0.5px'
                  }}
                >
                  Time Step
                </Box>
                
                {/* 2. Lifelines Header columns */}
                <Box sx={{ display: 'flex', width: activeEntities.length * 200, minWidth: activeEntities.length * 200 }}>
                  {activeEntities.map((entity, idx) => (
                    <Box 
                      key={idx} 
                      sx={{ 
                        width: 200, 
                        minWidth: 200, 
                        display: 'flex', 
                        flexDirection: 'column',
                        alignItems: 'center', 
                        justifyContent: 'center', 
                        borderRight: idx === activeEntities.length - 1 ? 'none' : '1px dashed #cbd5e1',
                        px: 1
                      }}
                    >
                      <Paper 
                        variant="outlined" 
                        sx={{ 
                          py: 0.5, 
                          px: 1.5, 
                          borderRadius: 2, 
                          borderColor: '#cbd5e1', 
                          background: '#ffffff',
                          boxShadow: '0 1px 2px rgba(0,0,0,0.05)',
                          maxWidth: 180,
                          textAlign: 'center',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap'
                        }}
                      >
                        <Typography 
                          variant="caption" 
                          sx={{ 
                            fontFamily: 'monospace', 
                            fontWeight: 700, 
                            color: '#0f172a',
                            fontSize: '11px'
                          }}
                        >
                          {entity}
                        </Typography>
                      </Paper>
                      <Typography variant="caption" sx={{ fontSize: '8px', color: '#64748b', fontWeight: 600, mt: 0.2 }}>
                        {visualizeBy === 'IP Address' ? 'ADDRESS' : visualizeBy.toUpperCase()}
                      </Typography>
                    </Box>
                  ))}
                </Box>
                
                {/* 3. Comments Column Header */}
                <Box 
                  sx={{ 
                    flexGrow: 1, 
                    display: 'flex', 
                    alignItems: 'center', 
                    pl: 2.5, 
                    fontWeight: 700, 
                    fontSize: '11px', 
                    color: '#475569', 
                    borderLeft: '1px solid #cbd5e1',
                    textTransform: 'uppercase',
                    letterSpacing: '0.5px'
                  }}
                >
                  Comment / Protocol Description
                </Box>
              </Box>

              {/* Rows List */}
              <Box sx={{ bgcolor: '#fdfdfd', flexGrow: 1 }}>
                {logs.filter(log => {
                  if (activeEntities.length === 0) return true;
                  const vals = getEntityValue(log, visualizeBy);
                  return vals.length > 0 && vals.every(v => activeEntities.includes(v));
                }).map((log, rowIdx) => {
                  const category = log.event_category || "Other";
                  const theme = PROTOCOL_THEMES[category] || PROTOCOL_THEMES["Other"];
                  const isCorrelated = log.correlated;
                  
                  // Get target entity endpoints
                  let srcVal = null;
                  let dstVal = null;
                  const entities = getEntityValue(log, visualizeBy);
                  if (entities.length > 0) {
                    if (visualizeBy === 'IP Address') {
                      srcVal = log.src_ip;
                      dstVal = log.dst_ip;
                    } else if (visualizeBy === 'Username') {
                      srcVal = log.src_user || log.dst_user;
                      dstVal = log.src_hostname || log.dst_hostname || log.dst_ip;
                    } else if (visualizeBy === 'Hostname') {
                      srcVal = log.src_hostname || log.dst_hostname;
                      dstVal = log.dst_ip || log.src_ip;
                    } else if (visualizeBy === 'Protocol') {
                      srcVal = log.protocol;
                      dstVal = log.application;
                    } else if (visualizeBy === 'Application') {
                      srcVal = log.application;
                      dstVal = log.process_name || log.protocol;
                    } else {
                      srcVal = entities[0];
                      dstVal = entities[1] || entities[0];
                    }
                  }

                  const srcIdx = srcVal ? activeEntities.indexOf(srcVal) : -1;
                  const dstIdx = dstVal ? activeEntities.indexOf(dstVal) : -1;

                  const columnWidth = 200;
                  const rowHeight = 46;
                  
                  const xSrc = srcIdx !== -1 ? srcIdx * columnWidth + columnWidth / 2 : -1;
                  const xDst = dstIdx !== -1 ? dstIdx * columnWidth + columnWidth / 2 : -1;
                  const y = rowHeight / 2;

                  // Determine row styling
                  let rowBgColor = theme.bg;
                  let rowBorderColor = theme.border;
                  
                  if (log.outcome && typeof log.outcome === "string" && log.outcome.trim().toLowerCase() === "failure") {
                    rowBgColor = "#fff5f5"; // soft failure tint
                    rowBorderColor = "#fee2e2";
                  }

                  // Build mid line label
                  let arrowLabel = log.protocol || "IP";
                  if (log.bytes) {
                    arrowLabel += ` Len=${log.bytes}`;
                  } else if (log.packet_count) {
                    arrowLabel += ` Pkts=${log.packet_count}`;
                  }
                  
                  if (log.severity && log.severity !== "Low") {
                    arrowLabel += ` [Sev:${log.severity}]`;
                  }

                  return (
                    <Box 
                      key={log.id} 
                      onClick={() => {
                        setSelectedEvent(log);
                        setDrawerOpen(true);
                      }}
                      sx={{ 
                        display: 'flex', 
                        height: rowHeight, 
                        bgcolor: rowBgColor, 
                        borderBottom: '1px solid #e2e8f0',
                        cursor: 'pointer',
                        transition: 'background-color 0.15s ease, transform 0.15s ease',
                        borderLeft: isCorrelated ? '4px solid #dc2626' : '4px solid transparent',
                        '&:hover': { 
                          bgcolor: isCorrelated ? '#ffe4e6' : '#f1f5f9',
                          boxShadow: 'inset 0 0 4px rgba(0,0,0,0.03)'
                        }
                      }}
                    >
                      {/* 1. Time Cell */}
                      <Box 
                        sx={{ 
                          width: 120, 
                          minWidth: 120, 
                          display: 'flex', 
                          alignItems: 'center', 
                          justifyContent: 'center', 
                          fontFamily: 'monospace', 
                          fontSize: '10.5px', 
                          color: isCorrelated ? '#991b1b' : '#475569', 
                          borderRight: '1px solid #cbd5e1',
                          fontWeight: 500
                        }}
                      >
                        {log.timestamp ? log.timestamp.split(' ')[1] || log.timestamp : '0.000000'}
                      </Box>

                      {/* 2. SVG Lifelines Area */}
                      <Box 
                        sx={{ 
                          width: activeEntities.length * columnWidth, 
                          minWidth: activeEntities.length * columnWidth, 
                          position: 'relative',
                          height: '100%'
                        }}
                      >
                        <svg 
                          style={{ 
                            position: 'absolute', 
                            top: 0, 
                            left: 0, 
                            width: '100%', 
                            height: '100%', 
                            overflow: 'visible',
                            pointerEvents: 'none'
                          }}
                        >
                          {/* Dotted Vertical Lifelines */}
                          {activeEntities.map((_, idx) => (
                            <line 
                              key={idx}
                              x1={idx * columnWidth + columnWidth / 2} 
                              y1={0} 
                              x2={idx * columnWidth + columnWidth / 2} 
                              y2={rowHeight} 
                              stroke="#cbd5e1" 
                              strokeDasharray="4 4"
                              strokeWidth={1.2}
                            />
                          ))}

                          {/* Horizontal Arrow Line */}
                          {srcIdx !== -1 && dstIdx !== -1 && (
                            <>
                              {/* Draw different arrow patterns for loopback vs standard cross-node */}
                              {srcIdx === dstIdx ? (
                                /* Loopback / Local action - U-turn path */
                                <path 
                                  d={`M ${xSrc} ${y - 8} H ${xSrc + 35} V ${y + 8} H ${xSrc}`} 
                                  fill="none" 
                                  stroke={theme.stroke} 
                                  strokeWidth={isCorrelated ? 2.5 : 1.5}
                                />
                              ) : (
                                /* Standard Directed Horizontal Arrow */
                                <line 
                                  x1={xSrc} 
                                  y1={y} 
                                  x2={xDst} 
                                  y2={y} 
                                  stroke={theme.stroke} 
                                  strokeWidth={isCorrelated ? 2.2 : 1.2}
                                />
                              )}

                              {/* Arrow Head Polygon */}
                              {srcIdx !== dstIdx ? (
                                <polygon 
                                  points={dstIdx > srcIdx 
                                    ? `${xDst},${y} ${xDst - 8},${y - 3.5} ${xDst - 8},${y + 3.5}` 
                                    : `${xDst},${y} ${xDst + 8},${y - 3.5} ${xDst + 8},${y + 3.5}`
                                  } 
                                  fill={theme.stroke}
                                />
                              ) : (
                                /* Loopback arrow head pointing back to lifeline */
                                <polygon 
                                  points={`${xSrc},${y + 8} ${xSrc + 6},${y + 5.5} ${xSrc + 6},${y + 10.5}`} 
                                  fill={theme.stroke}
                                />
                              )}

                              {/* Port Numbers next to the lifelines */}
                              {visualizeBy === 'IP Address' && srcIdx !== dstIdx && (
                                <>
                                  {log.src_port && (
                                    <text 
                                      x={dstIdx > srcIdx ? xSrc + 6 : xSrc - 6} 
                                      y={y - 4} 
                                      fontSize="8px" 
                                      fontFamily="monospace"
                                      fontWeight={600}
                                      fill="#64748b"
                                      textAnchor={dstIdx > srcIdx ? "start" : "end"}
                                    >
                                      {log.src_port}
                                    </text>
                                  )}
                                  {log.dst_port && (
                                    <text 
                                      x={dstIdx > srcIdx ? xDst - 6 : xDst + 6} 
                                      y={y - 4} 
                                      fontSize="8px" 
                                      fontFamily="monospace"
                                      fontWeight={600}
                                      fill="#64748b"
                                      textAnchor={dstIdx > srcIdx ? "end" : "start"}
                                    >
                                      {log.dst_port}
                                    </text>
                                  )}
                                </>
                              )}

                              {/* Centered Line Info Pill */}
                              {srcIdx !== dstIdx && (
                                <g>
                                  {/* White background pill container */}
                                  <rect 
                                    x={((xSrc + xDst) / 2) - 52} 
                                    y={y - 7.5} 
                                    width={104} 
                                    height={15} 
                                    fill="#ffffff" 
                                    rx={4} 
                                    stroke={isCorrelated ? "#fca5a5" : "#cbd5e1"} 
                                    strokeWidth={1}
                                  />
                                  {/* Label Text */}
                                  <text 
                                    x={(xSrc + xDst) / 2} 
                                    y={y + 3} 
                                    fontSize="8px" 
                                    fontFamily="monospace"
                                    fontWeight={700}
                                    textAnchor="middle" 
                                    fill={isCorrelated ? "#dc2626" : theme.text}
                                  >
                                    {arrowLabel}
                                  </text>
                                </g>
                              )}
                            </>
                          )}
                        </svg>
                      </Box>

                      {/* 3. Comments / Details Cell */}
                      <Box 
                        sx={{ 
                          flexGrow: 1, 
                          display: 'flex', 
                          alignItems: 'center', 
                          pl: 2.5,
                          pr: 2,
                          fontSize: '11px', 
                          borderLeft: '1px solid #cbd5e1',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap'
                        }}
                      >
                        {isCorrelated && (
                          <Chip 
                            label={`🚨 ALERT: ${log.incident_name}`} 
                            size="small" 
                            color="error" 
                            sx={{ height: 18, fontSize: '8.5px', fontWeight: 800, mr: 1, borderRadius: 1 }}
                          />
                        )}
                        <Typography 
                          variant="caption" 
                          sx={{ 
                            fontSize: '11.5px',
                            fontWeight: isCorrelated ? 700 : 500, 
                            color: isCorrelated ? '#991b1b' : '#334155',
                            fontFamily: 'Outfit, sans-serif'
                          }}
                        >
                          <strong>{log.event_name || 'Traffic Event'}</strong>
                          {log.application && ` via ${log.application}`}
                          {log.username && ` by User '${log.username}'`}
                          {log.hostname && ` on Host '${log.hostname}'`}
                          {log.risk_score && ` [Risk: ${log.risk_score}]`}
                          {log.outcome && ` (Status: ${log.outcome})`}
                        </Typography>
                      </Box>
                    </Box>
                  );
                })}
              </Box>
            </Box>
          </Box>
        )}
      </Box>

      {/* Forensic Details Drawer */}
      <Drawer
        anchor="right"
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        PaperProps={{
          sx: { width: { xs: '100%', sm: 480 }, p: 3, borderLeft: '1px solid #e2e8f0' }
        }}
      >
        {selectedEvent && (
          <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
            {/* Header */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
                <ShieldIcon color="primary" /> Log Analyzer
              </Typography>
              <IconButton onClick={() => setDrawerOpen(false)}>
                <CloseIcon />
              </IconButton>
            </Box>

            <Divider sx={{ mb: 3 }} />

            {/* Incident Highlight Badge */}
            {selectedEvent.correlated && (
              <Box sx={{ mb: 3, p: 2, bgcolor: '#fef2f2', border: '1px solid #fca5a5', borderRadius: 3.5 }}>
                <Typography variant="subtitle2" color="error.dark" sx={{ fontWeight: 700, mb: 0.5, display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <WarningAmberIcon sx={{ fontSize: 18 }} /> CORRELATED ALERT: {selectedEvent.incident_name}
                </Typography>
                <Typography variant="body2" color="error.dark" sx={{ fontSize: '0.8rem' }}>
                  This log is linked to an active alert. Severity Level is flagged as <strong>{selectedEvent.incident_severity}</strong>.
                </Typography>
              </Box>
            )}

            {/* Core Info */}
            <Box sx={{ flexGrow: 1, overflowY: 'auto', pr: 1 }}>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Paper variant="outlined" sx={{ p: 2, borderRadius: 2.5, bgcolor: '#f8fafc' }}>
                    <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block', mb: 0.5 }}>
                      EVENT NAME / DESCRIPTION
                    </Typography>
                    <Typography variant="body1" sx={{ fontWeight: 700, fontSize: '0.95rem' }}>
                      {selectedEvent.event_name}
                    </Typography>
                  </Paper>
                </Grid>

                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    TIMESTAMP
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', fontWeight: 600 }}>
                    {selectedEvent.timestamp}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    CATEGORY
                  </Typography>
                  <Chip 
                    label={selectedEvent.event_category} 
                    size="small" 
                    sx={{ 
                      bgcolor: `${(PROTOCOL_THEMES[selectedEvent.event_category] || PROTOCOL_THEMES["Other"]).stroke}15`, 
                      color: (PROTOCOL_THEMES[selectedEvent.event_category] || PROTOCOL_THEMES["Other"]).stroke,
                      fontWeight: 700,
                      borderRadius: 1.5,
                      mt: 0.5
                    }} 
                  />
                </Grid>

                <Grid item xs={12}><Divider /></Grid>

                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    SOURCE IP
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600, fontFamily: 'monospace' }}>
                    {selectedEvent.src_ip || "N/A"}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    DESTINATION IP
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600, fontFamily: 'monospace' }}>
                    {selectedEvent.dst_ip || "N/A"}
                  </Typography>
                </Grid>

                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    SOURCE PORT
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    {selectedEvent.src_port || "N/A"}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    DESTINATION PORT
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    {selectedEvent.dst_port || "N/A"}
                  </Typography>
                </Grid>

                <Grid item xs={12}><Divider /></Grid>

                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    USERNAME
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    {selectedEvent.src_user || selectedEvent.dst_user || "N/A"}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    HOSTNAME
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    {selectedEvent.src_hostname || selectedEvent.dst_hostname || "N/A"}
                  </Typography>
                </Grid>

                <Grid item xs={12}><Divider /></Grid>

                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    SEVERITY
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    {selectedEvent.severity || "N/A"}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    RISK SCORE
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: 700, color: (selectedEvent.extra_attributes?.confidence_score || selectedEvent.extra_attributes?.credibility || 0) > 70 ? 'error.main' : 'text.primary' }}>
                    {selectedEvent.extra_attributes?.confidence_score || selectedEvent.extra_attributes?.credibility || "N/A"}
                  </Typography>
                </Grid>

                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    PROTOCOL
                  </Typography>
                  <Typography variant="body2">
                    {selectedEvent.protocol || "N/A"}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    BYTES TRANSFERRED
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    {(selectedEvent.bytes_sent || selectedEvent.bytes_received) ? `${(selectedEvent.bytes_sent || 0) + (selectedEvent.bytes_received || 0)} bytes` : "N/A"}
                  </Typography>
                </Grid>

                {/* Extra Attributes */}
                {selectedEvent.extra_attributes && Object.keys(selectedEvent.extra_attributes).length > 0 && (
                  <>
                    <Grid item xs={12}><Divider /></Grid>
                    <Grid item xs={12}>
                      <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block', mb: 1 }}>
                        EXTRA ATTRIBUTES
                      </Typography>
                      <Paper variant="outlined" sx={{ p: 1.5, borderRadius: 2, bgcolor: '#f8fafc', maxHeight: 150, overflowY: 'auto' }}>
                        {Object.entries(selectedEvent.extra_attributes).map(([key, val]) => (
                          <Box key={key} sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                            <Typography variant="caption" sx={{ fontFamily: 'monospace', fontWeight: 600, color: 'text.secondary' }}>{key}</Typography>
                            <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>{String(val)}</Typography>
                          </Box>
                        ))}
                      </Paper>
                    </Grid>
                  </>
                )}

                {/* Playbook Recommendations */}
                <Grid item xs={12}><Divider /></Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: 'primary.main', display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    <TerminalIcon sx={{ fontSize: 16 }} /> Mitigation Playbook Instructions
                  </Typography>
                  <List dense sx={{ pl: 2, listStyleType: 'disc', '& .MuiListItem-root': { display: 'list-item', pl: 0 } }}>
                    {getPlaybook(selectedEvent.event_category, selectedEvent.event_name).map((rec, idx) => (
                      <ListItem key={idx}>
                        <ListItemText 
                          primary={rec} 
                          primaryTypographyProps={{ variant: 'body2', color: 'text.secondary' }} 
                        />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
              </Grid>
            </Box>
          </Box>
        )}
      </Drawer>
    </Box>
  );
}

export default AnalysisPage;
