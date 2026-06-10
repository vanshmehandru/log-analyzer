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

    const formData = new FormData();
    formData.append('file1', file1);
    formData.append('file2', file2);
    formData.append('file3', file3);

    try {
      const response = await axios.post(`${API_URL}/upload`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
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
    <Container maxWidth="md" sx={{ py: 6 }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 700, fontFamily: 'Outfit, sans-serif', letterSpacing: '-0.5px' }}>
        Ingest Security Log Sources
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph sx={{ mb: 4 }}>
        Select three CSV log sources to normalize event headers, classify threat categories, and run automated incident correlation rules.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 4, borderRadius: 2 }}>
          {error}
        </Alert>
      )}

      {uploads.length > 0 && !summary && (
        <Alert 
          severity="info" 
          sx={{ mb: 4, borderRadius: 3, p: 2, display: 'flex', alignItems: 'center' }} 
          action={
            <Box sx={{ display: 'flex', gap: 1.5 }}>
              <Button 
                variant="contained" 
                color="primary" 
                size="small" 
                onClick={() => navigate('/analysis')}
                sx={{ textTransform: 'none', fontWeight: 600, borderRadius: 1.5 }}
              >
                Go to Analysis
              </Button>
              <Button 
                variant="outlined" 
                color="error" 
                size="small" 
                onClick={handleClearDatabase}
                sx={{ textTransform: 'none', fontWeight: 600, borderRadius: 1.5 }}
              >
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
        <Card variant="outlined" sx={{ borderRadius: 3, mb: 4, boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.05)' }}>
          <CardContent sx={{ p: 4 }}>
            <Grid container spacing={3}>
              {/* Log Source 1 */}
              <Grid item xs={12}>
                <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1, color: 'text.secondary' }}>
                  Log Source 1 (Mandatory)
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Button
                    variant="outlined"
                    component="label"
                    startIcon={<CloudUploadIcon />}
                    sx={{ borderRadius: 2, textTransform: 'none' }}
                  >
                    Choose File
                    <input type="file" accept=".csv" hidden onChange={(e) => handleFileChange(e, 1)} />
                  </Button>
                  <Typography variant="body2" color={file1 ? "text.primary" : "text.secondary"} sx={{ fontStyle: file1 ? 'normal' : 'italic' }}>
                    {file1 ? file1.name : "No file chosen"}
                  </Typography>
                </Box>
              </Grid>

              <Grid item xs={12}><Divider /></Grid>

              {/* Log Source 2 */}
              <Grid item xs={12}>
                <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1, color: 'text.secondary' }}>
                  Log Source 2 (Mandatory)
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Button
                    variant="outlined"
                    component="label"
                    startIcon={<CloudUploadIcon />}
                    sx={{ borderRadius: 2, textTransform: 'none' }}
                  >
                    Choose File
                    <input type="file" accept=".csv" hidden onChange={(e) => handleFileChange(e, 2)} />
                  </Button>
                  <Typography variant="body2" color={file2 ? "text.primary" : "text.secondary"} sx={{ fontStyle: file2 ? 'normal' : 'italic' }}>
                    {file2 ? file2.name : "No file chosen"}
                  </Typography>
                </Box>
              </Grid>

              <Grid item xs={12}><Divider /></Grid>

              {/* Log Source 3 */}
              <Grid item xs={12}>
                <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1, color: 'text.secondary' }}>
                  Log Source 3 (Mandatory)
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Button
                    variant="outlined"
                    component="label"
                    startIcon={<CloudUploadIcon />}
                    sx={{ borderRadius: 2, textTransform: 'none' }}
                  >
                    Choose File
                    <input type="file" accept=".csv" hidden onChange={(e) => handleFileChange(e, 3)} />
                  </Button>
                  <Typography variant="body2" color={file3 ? "text.primary" : "text.secondary"} sx={{ fontStyle: file3 ? 'normal' : 'italic' }}>
                    {file3 ? file3.name : "No file chosen"}
                  </Typography>
                </Box>
              </Grid>
            </Grid>

            <Box sx={{ mt: 5, display: 'flex', justifyContent: 'flex-end' }}>
              <Button
                variant="contained"
                size="large"
                startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <CloudUploadIcon />}
                disabled={loading}
                onClick={handleUpload}
                sx={{ borderRadius: 2.5, px: 4, py: 1.5, textTransform: 'none', fontWeight: 600, boxShadow: 'none', '&:hover': { boxShadow: 'none' } }}
              >
                {loading ? "Normalizing..." : "Upload & Normalize"}
              </Button>
            </Box>
          </CardContent>
        </Card>
      ) : (
        <Card variant="outlined" sx={{ borderRadius: 3, mb: 4, overflow: 'hidden' }}>
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
  );
}

export default UploadPage;
