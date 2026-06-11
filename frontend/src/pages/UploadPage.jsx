import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { 
  Container, 
  Card, 
  CardContent, 
  Typography, 
  Button, 
  Grid, 
  Box, 
  Alert, 
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Divider
} from '@mui/material';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import BarChartIcon from '@mui/icons-material/BarChart';
import GridViewIcon from '@mui/icons-material/GridView';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import StorageIcon from '@mui/icons-material/Storage';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';

// Backend address
const API_URL = 'http://localhost:8000';

function UploadPage() {
  const navigate = useNavigate();
  const [file1, setFile1] = useState(null);
  const [file2, setFile2] = useState(null);
  const [file3, setFile3] = useState(null);
  
  const [uploads, setUploads] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(null);

  useEffect(() => {
    const fetchUploads = async () => {
      try {
        const response = await axios.get(`${API_URL}/uploads`);
        setUploads(response.data);
      } catch (err) {
        console.error("Failed to fetch uploads:", err);
      }
    };
    fetchUploads();
  }, []);

  const handleClearDatabase = async () => {
    if (!window.confirm("Are you sure you want to delete all uploaded logs and incidents? This cannot be undone.")) {
      return;
    }
    setLoading(true);
    try {
      await axios.post(`${API_URL}/upload/clear`);
      setUploads([]);
      setFile1(null);
      setFile2(null);
      setFile3(null);
      setError(null);
      setSummary(null);
    } catch (err) {
      console.error(err);
      setError("Failed to clear database.");
    } finally {
      setLoading(false);
    }
  };

  const handleFileChange = (e, index) => {
    const file = e.target.files[0];
    if (index === 1) setFile1(file);
    if (index === 2) setFile2(file);
    if (index === 3) setFile3(file);
    setError(null);
  };

  const handleUpload = async () => {
    // Validation
    if (!file1 || !file2 || !file3) {
      setError("Please upload all three log sources.");
      return;
    }

    setLoading(true);
    setError(null);
    setSummary(null);
    setUploadProgress(null);

    const formData = new FormData();
    formData.append('file1', file1);
    formData.append('file2', file2);
    formData.append('file3', file3);

    try {
      const response = await axios.post(`${API_URL}/upload`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        onUploadProgress: (progressEvent) => {
          if (progressEvent.lengthComputable) {
            setUploadProgress({
              loaded: progressEvent.loaded,
              total: progressEvent.total,
              percentage: Math.round((progressEvent.loaded * 100) / progressEvent.total)
            });
          }
        }
      });
      setSummary(response.data);
      // Refresh uploads list
      const uRes = await axios.get(`${API_URL}/uploads`);
      setUploads(uRes.data);
    } catch (err) {
      const msg = err.response?.data?.detail || "An error occurred during log normalization.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: 'calc(100vh - 64px)', bgcolor: '#f8fafc', pt: 6 }}>
      <Container maxWidth="md" sx={{ flexGrow: 1, pb: 6 }}>
        <Box sx={{ textAlign: 'center', mb: 5 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1.5, fontFamily: 'Inter, sans-serif', color: '#111827', letterSpacing: '-0.5px' }}>
            Security Log Correlation & <Box component="span" sx={{ color: '#0066FF' }}>Visualization</Box><br/>System
          </Typography>
          <Typography variant="body2" sx={{ color: '#4b5563', maxWidth: 600, mx: 'auto', lineHeight: 1.6 }}>
            Upload log sources to normalize, correlate, and visualize security events. Our precision engine isolates threats across distributed infrastructures.
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 4, borderRadius: 2, maxWidth: 650, mx: 'auto' }}>
            {error}
          </Alert>
        )}

        {uploads.length > 0 && !summary && (
          <Alert 
            severity="info" 
            sx={{ mb: 4, borderRadius: 2, p: 2, display: 'flex', alignItems: 'center', maxWidth: 650, mx: 'auto' }} 
            action={
              <Box sx={{ display: 'flex', gap: 1.5 }}>
                <Button variant="contained" color="primary" size="small" onClick={() => navigate('/analysis')} sx={{ textTransform: 'none', fontWeight: 600, borderRadius: 1.5 }}>
                  Go to Analysis
                </Button>
                <Button variant="outlined" color="error" size="small" onClick={handleClearDatabase} sx={{ textTransform: 'none', fontWeight: 600, borderRadius: 1.5 }}>
                  Clear Database
                </Button>
              </Box>
            }
          >
            <Box sx={{ pr: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                Active Database Session Found
              </Typography>
              <Typography variant="body2" sx={{ fontSize: '0.85rem', mt: 0.5 }}>
                The database contains {uploads.length} uploaded file(s) and associated logs. You can analyze them now or clear them to upload new logs.
              </Typography>
            </Box>
          </Alert>
        )}

        {!summary ? (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2.5, mb: 4, maxWidth: 650, mx: 'auto' }}>
            {[ 
              { id: 1, file: file1, title: 'Log Source 1', icon: <GridViewIcon sx={{ color: '#3b82f6', mr: 1.5, fontSize: 20 }}/> },
              { id: 2, file: file2, title: 'Log Source 2', icon: <AccountTreeIcon sx={{ color: '#3b82f6', mr: 1.5, fontSize: 20 }}/> },
              { id: 3, file: file3, title: 'Log Source 3', icon: <StorageIcon sx={{ color: '#3b82f6', mr: 1.5, fontSize: 20 }}/> }
            ].map((source) => (
              <Card key={source.id} variant="outlined" sx={{ borderRadius: 2, borderColor: '#e5e7eb', boxShadow: '0 1px 2px rgba(0,0,0,0.02)' }}>
                <CardContent sx={{ p: 2.5 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    {source.icon}
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, color: '#374151', fontSize: '0.9rem' }}>
                      {source.title}
                    </Typography>
                  </Box>
                  <Box 
                    component="label" 
                    sx={{ 
                      display: 'flex', 
                      flexDirection: 'column', 
                      alignItems: 'center', 
                      justifyContent: 'center',
                      p: 3, 
                      border: '1px dashed', 
                      borderColor: source.file ? '#3b82f6' : '#d1d5db', 
                      borderRadius: 1.5, 
                      bgcolor: source.file ? '#eff6ff' : '#ffffff',
                      cursor: 'pointer',
                      transition: 'all 0.2s ease',
                      '&:hover': { borderColor: '#3b82f6', bgcolor: '#f8fafc' }
                    }}
                  >
                    <CloudUploadIcon sx={{ fontSize: 32, color: '#6b7280', mb: 1 }} />
                    <Typography variant="body2" sx={{ color: '#4b5563', mb: 0.5, fontSize: '0.85rem' }}>
                      Drag and drop or <Box component="span" sx={{ color: '#0066FF', fontWeight: 600 }}>Browse file</Box>
                    </Typography>
                    <Typography variant="caption" sx={{ color: '#9ca3af', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                      {source.file ? source.file.name : "Accepted format: CSV"}
                    </Typography>
                    <input type="file" accept=".csv" hidden onChange={(e) => handleFileChange(e, source.id)} />
                  </Box>
                </CardContent>
              </Card>
            ))}

            <Card variant="outlined" sx={{ borderRadius: 2, borderColor: '#e5e7eb', bgcolor: '#f8fafc', mt: 1 }}>
              <CardContent sx={{ p: 2.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2.5 }}>
                  <InsertDriveFileIcon sx={{ color: '#3b82f6', mr: 1.5, fontSize: 20 }} />
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, color: '#374151', fontSize: '0.9rem' }}>
                    Upload Summary
                  </Typography>
                </Box>
                
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5, mb: 3 }}>
                  {[
                    { title: 'Log Source 1', file: file1 },
                    { title: 'Log Source 2', file: file2 },
                    { title: 'Log Source 3', file: file3 }
                  ].map((item, idx) => (
                    <Box key={idx} sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', bgcolor: '#ffffff', p: 1.5, borderRadius: 1.5, border: '1px solid #e5e7eb' }}>
                      <Typography variant="body2" sx={{ color: '#4b5563', fontSize: '0.85rem' }}>{item.title}</Typography>
                      <Typography variant="body2" sx={{ color: item.file ? '#10b981' : '#9ca3af', fontStyle: item.file ? 'normal' : 'italic', fontSize: '0.8rem' }}>
                        {item.file ? item.file.name : "Pending..."}
                      </Typography>
                    </Box>
                  ))}
                </Box>

                <Button
                  fullWidth
                  variant="contained"
                  disabled={!file1 || !file2 || !file3 || loading}
                  onClick={handleUpload}
                  sx={{ 
                    py: 1.5, 
                    borderRadius: 1.5, 
                    textTransform: 'none', 
                    fontWeight: 600,
                    bgcolor: (file1 && file2 && file3) ? '#a1a1aa' : '#d4d4d8', 
                    color: '#ffffff',
                    boxShadow: 'none',
                    '&:hover': { bgcolor: '#71717a', boxShadow: 'none' },
                    '&.Mui-disabled': {
                      bgcolor: '#d4d4d8',
                      color: '#ffffff'
                    }
                  }}
                >
                  {loading && uploadProgress && uploadProgress.percentage < 100 
                    ? `Uploading... ${uploadProgress.percentage}%` 
                    : loading ? "Normalizing..." : "Continue to Analysis"}
                </Button>
                <Typography variant="caption" sx={{ display: 'block', textAlign: 'center', mt: 2, color: '#6b7280', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                  All three files must be verified for system correlation.
                </Typography>
              </CardContent>
            </Card>
          </Box>
        ) : (
          <Card variant="outlined" sx={{ borderRadius: 2, mb: 4, overflow: 'hidden', maxWidth: 650, mx: 'auto' }}>
            <Box sx={{ bgcolor: 'success.light', p: 3, color: 'success.dark', display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <CheckCircleIcon />
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                Logs Successfully Ingested and Correlated
              </Typography>
            </Box>
            <CardContent sx={{ p: 4 }}>
              <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600, mb: 2 }}>
                Normalization Summary
              </Typography>
              <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2, mb: 4 }}>
                <Table>
                  <TableHead sx={{ bgcolor: '#f8fafc' }}>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 600 }}>File Name</TableCell>
                      <TableCell align="right" sx={{ fontWeight: 600 }}>Record Count</TableCell>
                      <TableCell align="center" sx={{ fontWeight: 600 }}>Normalization Status</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {summary.files.map((file, idx) => (
                      <TableRow key={idx}>
                        <TableCell>{file.file_name}</TableCell>
                        <TableCell align="right">{file.record_count.toLocaleString()}</TableCell>
                        <TableCell align="center">
                          <Box sx={{ display: 'inline-flex', px: 1.5, py: 0.5, bgcolor: 'success.lighter', color: 'success.main', borderRadius: 1.5, fontSize: '0.75rem', fontWeight: 600 }}>
                            {file.status}
                          </Box>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Grid container spacing={3} sx={{ mb: 4 }}>
                <Grid item xs={6}>
                  <Box sx={{ p: 3, border: '1px solid #e2e8f0', borderRadius: 3, textAlign: 'center', bgcolor: '#f8fafc' }}>
                    <Typography variant="h4" sx={{ fontWeight: 700, color: 'primary.main', mb: 0.5 }}>
                      {summary.total_records.toLocaleString()}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Total Records Processed
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Box sx={{ p: 3, border: '1px solid #e2e8f0', borderRadius: 3, textAlign: 'center', bgcolor: summary.total_incidents > 0 ? '#fef2f2' : '#f8fafc' }}>
                    <Typography variant="h4" sx={{ fontWeight: 700, color: summary.total_incidents > 0 ? 'error.main' : 'text.primary', mb: 0.5 }}>
                      {summary.total_incidents}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Total Incidents Generated
                    </Typography>
                  </Box>
                </Grid>
              </Grid>

              <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
                <Button
                  variant="outlined"
                  onClick={() => setSummary(null)}
                  sx={{ borderRadius: 2, textTransform: 'none' }}
                >
                  Upload New Batch
                </Button>
                <Button
                  variant="contained"
                  size="large"
                  startIcon={<BarChartIcon />}
                  onClick={() => navigate('/analysis')}
                  sx={{ borderRadius: 2.5, px: 4, textTransform: 'none', fontWeight: 600, boxShadow: 'none', '&:hover': { boxShadow: 'none' } }}
                >
                  Generate Analysis
                </Button>
              </Box>
            </CardContent>
          </Card>
        )}
      </Container>
      
      <Box sx={{ borderTop: '1px solid #e5e7eb', py: 2, px: { xs: 2, md: 4 }, display: 'flex', justifyContent: 'space-between', alignItems: 'center', bgcolor: '#f3f4f6' }}>
        <Typography variant="caption" sx={{ color: '#6b7280', fontFamily: 'monospace', fontSize: '0.7rem' }}>
          © 2024 Sentinel Security Systems. All Rights Reserved.
        </Typography>
        <Box sx={{ display: 'flex', gap: 3 }}>
          <Typography variant="caption" sx={{ color: '#6b7280', fontFamily: 'monospace', cursor: 'pointer', fontSize: '0.7rem', '&:hover': { color: '#374151' } }}>Privacy Policy</Typography>
          <Typography variant="caption" sx={{ color: '#6b7280', fontFamily: 'monospace', cursor: 'pointer', fontSize: '0.7rem', '&:hover': { color: '#374151' } }}>Terms of Service</Typography>
          <Typography variant="caption" sx={{ color: '#6b7280', fontFamily: 'monospace', cursor: 'pointer', fontSize: '0.7rem', '&:hover': { color: '#374151' } }}>Security Standards</Typography>
        </Box>
      </Box>
    </Box>
  );
}

export default UploadPage;
