// src/services/pythonService.js - VERCEL COMPATIBLE
const { spawn } = require('child_process');
const path = require('path');

class PythonService {
  static async executeScan(targetUrl) {
    return new Promise((resolve, reject) => {
      const scriptPath = path.join(__dirname, '../../scanner.py');
      
      // Vercel uses 'python3.9' or 'python' depending on the runtime
      // Try multiple python commands in order
      const pythonCommands = ['python3.9', 'python3', 'python'];
      
      // Detect if running on Vercel or locally
      const isVercel = process.env.VERCEL === '1' || process.env.NOW_REGION;
      const pythonCmd = isVercel ? 'python3.9' : (process.platform === 'win32' ? 'python' : 'python3');
      
      console.log(`Executing Python scanner: ${pythonCmd} ${scriptPath}`);
      console.log(`Target URL: ${targetUrl}`);
      console.log(`Environment: ${isVercel ? 'Vercel' : 'Local'}`);
      
      const pythonProcess = spawn(pythonCmd, [scriptPath, targetUrl], {
        env: {
          ...process.env,
          PYTHONPATH: path.join(__dirname, '../../'),
          PYTHONUNBUFFERED: '1'
        }
      });
      
      let outputData = '';
      let errorData = '';
      
      pythonProcess.stdout.on('data', (data) => {
        outputData += data.toString();
      });
      
      pythonProcess.stderr.on('data', (data) => {
        errorData += data.toString();
        console.log('Scanner log:', data.toString());
      });
      
      pythonProcess.on('close', (code) => {
        if (code !== 0) {
          console.error('Scanner failed with code:', code);
          console.error('Error output:', errorData);
          return reject(new Error(`Scanner failed with code ${code}: ${errorData}`));
        }
        
        try {
          const result = JSON.parse(outputData);
          console.log('Scan completed:', {
            url: result.targetUrl,
            vulnerabilities: result.vulnerabilitiesFound
          });
          resolve(result);
        } catch (parseError) {
          console.error('Failed to parse scanner output:', outputData);
          reject(new Error(`Failed to parse scanner output: ${parseError.message}`));
        }
      });
      
      pythonProcess.on('error', (error) => {
        console.error('Failed to start Python process:', error);
        reject(new Error(`Failed to start scanner: ${error.message}`));
      });
      
      setTimeout(() => {
        pythonProcess.kill();
        reject(new Error('Scan timeout - operation took too long'));
      }, 60000);
    });
  }
}

module.exports = PythonService;
