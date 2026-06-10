import React, { useState, useEffect } from 'react';
import axios from 'axios';
import ReactFlow, { 
  Controls, 
  Background, 
  useNodesState, 
  useEdgesState,
  MarkerType 
} from 'reactflow';
import 'reactflow/dist/style.css';
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
  Paper
} from '@mui/material';
import FilterListIcon from '@mui/icons-material/FilterList';
import CloseIcon from '@mui/icons-material/Close';
import ShieldIcon from '@mui/icons-material/Shield';
import RefreshIcon from '@mui/icons-material/Refresh';

const API_URL = 'http://localhost:8000';

// Event category color definitions
const CATEGORY_COLORS = {
  "Authentication": "#3b82f6", // Blue
  "DNS": "#22c55e",            // Green
  "Reconnaissance": "#f97316", // Orange
  "Malware": "#ef4444",        // Red
  "System": "#64748b",         // Gray
  "Network": "#a855f7",        // Purple
  "Other": "#94a3b8"           // Default Slate
};

function AnalysisPage() {
  const [logs, setLogs] = useState([]);
  const [uploads, setUploads] = useState([]);
  
  // Filter states
  const [visualizeBy, setVisualizeBy] = useState('Source IP');
  const [timeRange, setTimeRange] = useState('all');
  const [eventCategory, setEventCategory] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [sourceLog, setSourceLog] = useState('all');
  
  // React Flow states
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  
  // Details Drawer state
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [loading, setLoading] = useState(false);

  // Fetch log sources for filters
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

  // Fetch logs and construct graph
  const generateVisualization = async () => {
    setLoading(true);
    try {
      const params = {};
      if (eventCategory !== 'all') params.event_category = eventCategory;
      if (severity !== 'all') params.severity = severity;
      if (sourceLog !== 'all') params.source_log = sourceLog;
      if (timeRange !== 'all') params.time_range = timeRange;

      const response = await axios.get(`${API_URL}/logs/flow`, { params });
      const logsData = response.data;
      setLogs(logsData);
      buildFlowGraph(logsData, visualizeBy);
    } catch (err) {
      console.error("Failed to query flow logs:", err);
    } finally {
      setLoading(false);
    }
  };

  // Run initial query
  useEffect(() => {
    generateVisualization();
  }, []);

  // Build nodes and edges for React Flow
  const buildFlowGraph = (data, visualAttr) => {
    if (!data || data.length === 0) {
      setNodes([]);
      setEdges([]);
      return;
    }

    // 1. Identify unique lanes (entities)
    const getEntities = (log) => {
      switch (visualAttr) {
        case 'Source IP':
          return { src: log.src_ip || "Unknown", dst: log.dst_ip || "Unknown" };
        case 'Destination IP':
          return { src: log.src_ip || "Unknown", dst: log.dst_ip || "Unknown" };
        case 'Username':
          return { src: log.username || "System", dst: log.hostname || log.dst_ip || "Target" };
        case 'Hostname':
          return { src: log.hostname || "SourceHost", dst: log.dst_ip || "Destination" };
        case 'Event Category':
          return { src: log.event_category || "Other", dst: log.event_name || "Event" };
        case 'Protocol':
          return { src: log.protocol || "Any", dst: log.application || "Traffic" };
        case 'Destination Port':
          return { src: log.src_ip || "Source", dst: log.dst_port ? String(log.dst_port) : "Any" };
        case 'Application':
          return { src: log.application || "App", dst: log.process_name || "Process" };
        case 'Process Name':
          return { src: log.process_name || "Process", dst: log.hostname || "Host" };
        default:
          return { src: log.src_ip || "Source", dst: log.dst_ip || "Destination" };
      }
    };

    const uniqueLanesSet = new Set();
    data.forEach(log => {
      const { src, dst } = getEntities(log);
      uniqueLanesSet.add(src);
      uniqueLanesSet.add(dst);
    });

    const lanes = Array.from(uniqueLanesSet);
    
    // Position lanes horizontally
    const lanePositions = {};
    lanes.forEach((lane, idx) => {
      lanePositions[lane] = idx * 250;
    });

    const newNodes = [];
    const newEdges = [];
    const maxY = data.length * 80 + 150;

    // 2. Render Header Nodes (Entity Lanes at top)
    lanes.forEach(lane => {
      const x = lanePositions[lane];
      // Column Header
      newNodes.push({
        id: `header:${lane}`,
        position: { x: x, y: 10 },
        data: { label: lane },
        style: {
          background: '#ffffff',
          color: '#1e293b',
          border: '2px solid #cbd5e1',
          padding: '10px 15px',
          fontWeight: '700',
          fontSize: '13px',
          width: 180,
          textAlign: 'center',
          boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
        },
        type: 'input',
        draggable: false
      });

      // Bottom boundary anchor for vertical lane lines
      newNodes.push({
        id: `footer:${lane}`,
        position: { x: x + 90, y: maxY },
        data: { label: '' },
        style: { opacity: 0, width: 0, height: 0, padding: 0 },
        draggable: false
      });

      // Vertical dotted lane lifeline edge
      newEdges.push({
        id: `line:${lane}`,
        source: `header:${lane}`,
        target: `footer:${lane}`,
        style: { stroke: '#cbd5e1', strokeDasharray: '5 5', strokeWidth: 1.5 },
        className: 'flow-lane-line',
        focusable: false,
        selectable: false
      });
    });

    // 3. Render Events and Arrows
    data.forEach((log, idx) => {
      const y = 100 + idx * 80;
      const { src, dst } = getEntities(log);
      const xSrc = lanePositions[src] + 90; // offset to center of the 180px wide header
      const xDst = lanePositions[dst] + 90;

      // Y-Axis Time node on the left
      newNodes.push({
        id: `time:${log.id}`,
        position: { x: -180, y: y - 10 },
        data: { label: log.timestamp || "0.0" },
        style: {
          background: '#f1f5f9',
          color: '#64748b',
          border: 'none',
          padding: '4px 8px',
          fontSize: '11px',
          fontFamily: 'monospace',
          fontWeight: 600,
          width: 100,
          textAlign: 'right'
        },
        draggable: false
      });

      // Anchor nodes on the lifelines
      const srcAnchorId = `anchor-src:${log.id}`;
      const dstAnchorId = `anchor-dst:${log.id}`;

      newNodes.push({
        id: srcAnchorId,
        position: { x: xSrc, y: y },
        data: { label: '' },
        style: { background: CATEGORY_COLORS[log.event_category] || CATEGORY_COLORS["Other"], border: 'none', width: 8, height: 8, borderRadius: '50%' },
        draggable: false
      });

      newNodes.push({
        id: dstAnchorId,
        position: { x: xDst, y: y },
        data: { label: '' },
        style: { background: CATEGORY_COLORS[log.event_category] || CATEGORY_COLORS["Other"], border: 'none', width: 8, height: 8, borderRadius: '50%' },
        draggable: false
      });

      // Conversation Directed Edge (Arrow)
      const edgeColor = CATEGORY_COLORS[log.event_category] || CATEGORY_COLORS["Other"];
      const isCorrelated = log.correlated;

      newEdges.push({
        id: `edge:${log.id}`,
        source: srcAnchorId,
        target: dstAnchorId,
        label: log.event_name,
        labelStyle: { fill: isCorrelated ? '#ef4444' : '#1e293b', fontWeight: isCorrelated ? 700 : 500, fontSize: '11px' },
        labelBgPadding: 4,
        labelBgBorderRadius: 4,
        labelBgStyle: { fill: '#ffffff', fillOpacity: 0.95, stroke: isCorrelated ? '#fca5a5' : '#e2e8f0', strokeWidth: 1 },
        style: {
          stroke: isCorrelated ? '#ef4444' : edgeColor,
          strokeWidth: isCorrelated ? 3.5 : 2,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          width: 15,
          height: 15,
          color: isCorrelated ? '#ef4444' : edgeColor,
        },
        className: isCorrelated ? 'correlated' : '',
        data: { log } // pass raw log for edge click
      });
    });

    setNodes(newNodes);
    setEdges(newEdges);
  };

  const handleEdgeClick = (event, edge) => {
    if (edge.data && edge.data.log) {
      setSelectedEvent(edge.data.log);
      setDrawerOpen(true);
    }
  };

  // Simple recommendations compiler helper
  const getPlaybook = (category, name) => {
    if (category === "Authentication") {
      return [
        "Isolate account session and enforce password rotation.",
        "Verify geographical access details and source location.",
        "Audit log history for concurrent logins across IP addresses."
      ];
    }
    if (category === "Reconnaissance" || name.toLowerCase().includes("scan")) {
      return [
        "Temporarily block source IP address at perimeter gateway.",
        "Check firewall policy rules on targeted destination ports.",
        "Ensure host defense systems are actively dropping scan packets."
      ];
    }
    if (category === "Malware" || name.toLowerCase().includes("malware")) {
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
    <Box sx={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 64px)', overflow: 'hidden' }}>
      {/* Filtering Control Bar */}
      <Paper variant="outlined" sx={{ p: 2, m: 2, borderRadius: 3, border: '1px solid #e2e8f0', boxShadow: 'none' }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} sm={6} md={2.5}>
            <FormControl fullWidth size="small">
              <InputLabel>Visualize By</InputLabel>
              <Select
                value={visualizeBy}
                label="Visualize By"
                onChange={(e) => setVisualizeBy(e.target.value)}
              >
                <MenuItem value="Source IP">Source IP</MenuItem>
                <MenuItem value="Destination IP">Destination IP</MenuItem>
                <MenuItem value="Username">Username</MenuItem>
                <MenuItem value="Hostname">Hostname</MenuItem>
                <MenuItem value="Event Category">Event Category</MenuItem>
                <MenuItem value="Protocol">Protocol</MenuItem>
                <MenuItem value="Destination Port">Destination Port</MenuItem>
                <MenuItem value="Application">Application</MenuItem>
                <MenuItem value="Process Name">Process Name</MenuItem>
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} sm={6} md={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Time Range</InputLabel>
              <Select
                value={timeRange}
                label="Time Range"
                onChange={(e) => setTimeRange(e.target.value)}
              >
                <MenuItem value="all">All Timelines</MenuItem>
                <MenuItem value="last_5_minutes">Last 5 Minutes</MenuItem>
                <MenuItem value="last_hour">Last Hour</MenuItem>
                <MenuItem value="last_24_hours">Last 24 Hours</MenuItem>
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} sm={6} md={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Event Category</InputLabel>
              <Select
                value={eventCategory}
                label="Event Category"
                onChange={(e) => setEventCategory(e.target.value)}
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

          <Grid item xs={12} sm={6} md={1.5}>
            <FormControl fullWidth size="small">
              <InputLabel>Severity</InputLabel>
              <Select
                value={severity}
                label="Severity"
                onChange={(e) => setSeverity(e.target.value)}
              >
                <MenuItem value="all">All Levels</MenuItem>
                <MenuItem value="Low">Low</MenuItem>
                <MenuItem value="Medium">Medium</MenuItem>
                <MenuItem value="High">High</MenuItem>
                <MenuItem value="Critical">Critical</MenuItem>
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} sm={6} md={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Source Log</InputLabel>
              <Select
                value={sourceLog}
                label="Source Log"
                onChange={(e) => setSourceLog(e.target.value)}
              >
                <MenuItem value="all">All Files</MenuItem>
                {uploads.map((upload) => (
                  <MenuItem key={upload.id} value={upload.file_name}>
                    {upload.file_name}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} sm={6} md={2} sx={{ display: 'flex', gap: 1 }}>
            <Button
              variant="contained"
              fullWidth
              startIcon={<FilterListIcon />}
              onClick={generateVisualization}
              disabled={loading}
              sx={{ borderRadius: 2, textTransform: 'none', fontWeight: 600, boxShadow: 'none', '&:hover': { boxShadow: 'none' } }}
            >
              Generate
            </Button>
            <IconButton onClick={generateVisualization} disabled={loading} color="primary">
              <RefreshIcon />
            </IconButton>
          </Grid>
        </Grid>
      </Paper>

      {/* Main Graph Canvas */}
      <Box sx={{ flexGrow: 1, position: 'relative', m: 2, mt: 0, border: '1px solid #e2e8f0', borderRadius: 3, bgcolor: '#ffffff', overflow: 'hidden' }}>
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
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onEdgeClick={handleEdgeClick}
            fitView
            minZoom={0.1}
            maxZoom={1.5}
            nodesDraggable={false}
          >
            <Controls />
            <Background color="#cbd5e1" gap={20} size={1} />
          </ReactFlow>
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
                <ShieldIcon color="primary" /> Event Forensic Triage
              </Typography>
              <IconButton onClick={() => setDrawerOpen(false)}>
                <CloseIcon />
              </IconButton>
            </Box>

            <Divider sx={{ mb: 3 }} />

            {/* Incident Highlight Badge */}
            {selectedEvent.correlated && (
              <Box sx={{ mb: 3, p: 2, bgcolor: '#fef2f2', border: '1px solid #fca5a5', borderRadius: 3.5 }}>
                <Typography variant="subtitle2" color="error.dark" sx={{ fontWeight: 700, mb: 0.5 }}>
                  🚨 CORRELATED SECURITY ALERT: {selectedEvent.incident_name}
                </Typography>
                <Typography variant="body2" color="error.dark">
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
                      EVENT NAME
                    </Typography>
                    <Typography variant="body1" sx={{ fontWeight: 600 }}>
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
                      bgcolor: `${CATEGORY_COLORS[selectedEvent.event_category] || CATEGORY_COLORS["Other"]}15`, 
                      color: CATEGORY_COLORS[selectedEvent.event_category] || CATEGORY_COLORS["Other"],
                      fontWeight: 600,
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
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    {selectedEvent.src_ip || "N/A"}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    DESTINATION IP
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    {selectedEvent.dst_ip || "N/A"}
                  </Typography>
                </Grid>

                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    USERNAME
                  </Typography>
                  <Typography variant="body2">
                    {selectedEvent.username || "N/A"}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block' }}>
                    HOSTNAME
                  </Typography>
                  <Typography variant="body2">
                    {selectedEvent.hostname || "N/A"}
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
                  <Typography variant="body2" sx={{ fontWeight: 600, color: selectedEvent.risk_score > 7 ? 'error.main' : 'text.primary' }}>
                    {selectedEvent.risk_score || "N/A"}
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
                    SOURCE LOG
                  </Typography>
                  <Typography variant="body2" sx={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>
                    {selectedEvent.source_log || "N/A"}
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

                {/* Analyst Playbook Recommendations */}
                <Grid item xs={12}><Divider /></Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: 'primary.main' }}>
                    Mitigation Playbook
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
