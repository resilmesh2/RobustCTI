<template>
  <div class="integration-tools-dialog-overlay" :class="{ hidden: !isShowingIntegrationToolsDialog }" @click.self="closeDialog">
    <div class="integration-tools-dialog">
      <div class="dialog-header">
        <h2>Integration Tools</h2>
        <div class="close-button" @click="closeDialog">
          <Close color="#8c8c8c" />
        </div>
      </div>
      <TabBox class="dialog-content" v-model="activeTab" :canClose="false">
        <Tab name="STIX Visualization">
          <div class="tab-content">
            <div class="tab-header">
              <h2>STIX Visualization</h2>
              <p class="description">Interactive STIX object creation and editing tool from Johns Hopkins APL.</p>
            </div>
            
            <div class="button-group">
              <button class="secondary-button" @click="launchStixVisualizer">Launch STIX Visualizer</button>
              <button class="secondary-button" @click="launchStixModeler">Launch STIX Modeler</button>
            </div>

            <div class="features-section">
              <h3>Features:</h3>
              <ul class="features-list">
                <li>STIX data visualization and exploration</li>
                <li>Real-time collaboration and analysis</li>
              </ul>
            </div>
          </div>
        </Tab>
        <Tab name="Atomic Attack Emulation">
          <div class="tab-content">
            <div class="tab-header">
              <h2>Atomic Attack Emulation</h2>
              <p class="description">Execute atomic tests to emulate adversary techniques for defense validation.</p>
            </div>
            
            <div class="config-sections-container">
              <div class="server-config-section">
                <h3>AtomicRedTeam Server</h3>
                <div class="inline-form-group">
                  <label for="server-ip">IP Address:</label>
                  <input type="text" id="server-ip" v-model="serverConfig.ipAddress" placeholder="192.168.1.100" />
                </div>
                <div class="inline-form-group">
                  <label for="server-port">Port:</label>
                  <input type="number" id="server-port" v-model="serverConfig.port" placeholder="e.g. 22, 2222" />
                </div>
                <div class="inline-form-group">
                  <label for="server-username">Username:</label>
                  <input type="text" id="server-username" v-model="serverConfig.username" placeholder="kali" />
                </div>
                <div class="inline-form-group">
                  <label for="server-password">Password:</label>
                  <input type="password" id="server-password" v-model="serverConfig.password" placeholder="Enter password" />
                </div>
              </div>

              <div class="target-host-section">
                <h3>Target Host</h3>
                <div class="inline-form-group">
                  <label for="target-ip">IP Address:</label>
                  <input type="text" id="target-ip" v-model="targetConfig.ipAddress" placeholder="192.168.1.100" />
                </div>
                <div class="inline-form-group">
                  <label for="target-port">Port:</label>
                  <input type="number" id="target-port" v-model="targetConfig.port" placeholder="e.g. 22, 2222" />
                </div>
                <div class="inline-form-group">
                  <label for="target-username">Username:</label>
                  <input type="text" id="target-username" v-model="targetConfig.username" placeholder="administrator" />
                </div>
                <div class="inline-form-group">
                  <label for="target-password">Password:</label>
                  <input type="password" id="target-password" v-model="targetConfig.password" placeholder="Enter password" />
                </div>
                <div class="inline-form-group">
                  <label for="target-os">OS:</label>
                  <select id="target-os" v-model="targetConfig.os" class="os-select-inline">
                    <option value="">Select OS</option>
                    <option value="linux">Linux</option>
                    <option value="windows">Windows</option>
                  </select>
                </div>
              </div>
            </div>

            <div class="schedule-file-section">
              <h3>Schedule File</h3>
              <p class="description">Upload a CSV file containing the attack schedule and configuration.</p>
              
              <div class="file-upload-area" :class="{ 'drag-over': isDragOver }" 
                   @dragenter="onDragEnter" 
                   @dragover="onDragOver" 
                   @dragleave="onDragLeave" 
                   @drop="onDrop"
                   @click="triggerFileInput">
                <input type="file" ref="fileInput" @change="onFileSelect" accept=".csv" class="file-input" />
                <div class="upload-content">
                  <div v-if="!uploadedFile" class="upload-placeholder">
                    <span class="upload-icon">📁</span>
                    <p>Click to browse or drag and drop CSV file</p>
                    <small>Only .csv files are allowed (max 5MB)</small>
                  </div>
                  <div v-else class="uploaded-file">
                    <span class="file-icon">📄</span>
                    <div class="file-info">
                      <p class="file-name">{{ uploadedFile.name }}</p>
                      <small class="file-size">{{ formatFileSize(uploadedFile.size) }}</small>
                    </div>
                    <button class="remove-file" @click.stop="removeFile">✕</button>
                  </div>
                </div>
              </div>
              
              <div v-if="fileError" class="error-message">
                {{ fileError }}
              </div>
            </div>

            <div class="launch-test-section">
              <button class="launch-test-button" @click="launchTest">Launch Test</button>
            </div>
          </div>
        </Tab>
      </TabBox>
    </div>
  </div>
</template>

<script lang="ts">
import * as App from "@/store/Commands/AppCommands";
// Dependencies
import { defineComponent } from "vue";
import { mapGetters, mapMutations } from "vuex";
// Components
import Close from "@/components/Icons/Close.vue";
import Tab from "@/components/Containers/Tab.vue";
import TabBox from "@/components/Containers/TabBox.vue";

export default defineComponent({
  name: "IntegrationToolsDialog",
  data() {
    return {
      activeTab: 0,
      serverConfig: {
        ipAddress: '',
        port: '',
        username: '',
        password: ''
      },
      targetConfig: {
        ipAddress: '',
        port: '',
        username: '',
        password: '',
        os: ''
      },
      uploadedFile: null as File | null,
      isDragOver: false,
      fileError: ''
    };
  },
  computed: {
    ...mapGetters("ApplicationStore", ["isShowingIntegrationToolsDialog"])
  },
  methods: {
    /**
     * Application Store mutations
     */
    ...mapMutations("ApplicationStore", ["execute"]),

    /**
     * Close the integration tools dialog
     */
    closeDialog() {
      // Get the ApplicationStore from Vuex
      const appStore = (this as any).$store.state.ApplicationStore;
      this.execute(new App.HideIntegrationToolsDialog(appStore));
    },

    /**
     * Launch the STIX Visualizer in a new tab/window
     */
    launchStixVisualizer() {
      window.open('/cti-stix-visualization/index.html', '_blank');
    },

    /**
     * Launch the local STIX Modeler application
     */
    launchStixModeler() {
      const stixModelerUrl = "http://localhost:3000";
      window.open(stixModelerUrl, "_blank", "noopener,noreferrer");
    },

    /**
     * File upload methods
     */
    triggerFileInput() {
      const fileInput = this.$refs.fileInput as HTMLInputElement;
      fileInput?.click();
    },

    onFileSelect(event: Event) {
      const target = event.target as HTMLInputElement;
      const file = target.files?.[0];
      if (file) {
        this.validateAndSetFile(file);
      }
    },

    onDragEnter(event: DragEvent) {
      event.preventDefault();
      this.isDragOver = true;
    },

    onDragOver(event: DragEvent) {
      event.preventDefault();
    },

    onDragLeave(event: DragEvent) {
      event.preventDefault();
      this.isDragOver = false;
    },

    onDrop(event: DragEvent) {
      event.preventDefault();
      this.isDragOver = false;
      const files = event.dataTransfer?.files;
      if (files && files.length > 0) {
        this.validateAndSetFile(files[0]);
      }
    },

    validateAndSetFile(file: File) {
      this.fileError = '';
      
      // Check file type
      if (!file.name.toLowerCase().endsWith('.csv')) {
        this.fileError = 'Only CSV files are allowed.';
        return;
      }

      // Check MIME type for additional security
      if (file.type && !file.type.includes('csv') && !file.type.includes('text/')) {
        this.fileError = 'Invalid file type. Only CSV files are allowed.';
        return;
      }

      // Check file size (5MB limit)
      const maxSize = 5 * 1024 * 1024; // 5MB in bytes
      if (file.size > maxSize) {
        this.fileError = 'File size exceeds 5MB limit.';
        return;
      }

      // Check for suspicious file names
      const suspiciousPatterns = [/\.exe$/i, /\.bat$/i, /\.sh$/i, /\.js$/i, /\.php$/i];
      if (suspiciousPatterns.some(pattern => pattern.test(file.name))) {
        this.fileError = 'File name contains suspicious patterns.';
        return;
      }

      this.uploadedFile = file;
    },

    removeFile() {
      this.uploadedFile = null;
      this.fileError = '';
      const fileInput = this.$refs.fileInput as HTMLInputElement;
      if (fileInput) {
        fileInput.value = '';
      }
    },

    formatFileSize(bytes: number): string {
      if (bytes === 0) return '0 Bytes';
      const k = 1024;
      const sizes = ['Bytes', 'KB', 'MB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    /**
     * Launch test with configured settings
     */
    async launchTest() {
      // Validate required fields
      if (!this.serverConfig.ipAddress || !this.targetConfig.ipAddress) {
        alert('Please fill in at least the IP addresses for both server and target.');
        return;
      }

      if (!this.serverConfig.username || !this.serverConfig.password) {
        alert('Please fill in username and password for the Kali server.');
        return;
      }

      if (!this.targetConfig.username || !this.targetConfig.password) {
        alert('Please fill in username and password for the target host.');
        return;
      }

      if (!this.uploadedFile) {
        alert('Please upload a schedule file.');
        return;
      }

      // Show loading state
      const launchButton = document.querySelector('.launch-test-button') as HTMLButtonElement;
      const originalText = launchButton?.textContent || 'Launch Test';

      try {
        if (launchButton) {
          launchButton.textContent = 'Launching Test...';
          launchButton.disabled = true;
        }

        // Step 1: Upload schedule file to backend and transfer to Kali
        console.log('Step 1: Uploading schedule file...');

        const formData = new FormData();
        formData.append('file', this.uploadedFile);
        formData.append('server_ip', this.serverConfig.ipAddress);
        formData.append('server_username', this.serverConfig.username);
        formData.append('server_password', this.serverConfig.password);
        formData.append('server_port', this.serverConfig.port || '22');

        const uploadResponse = await fetch('/api/upload-schedule', {
          method: 'POST',
          body: formData
        });

        if (!uploadResponse.ok) {
          throw new Error(`File upload failed: ${uploadResponse.statusText}`);
        }

        const uploadResult = await uploadResponse.json();
        console.log('File upload result:', uploadResult);

        if (uploadResult.status !== 'success') {
          throw new Error(`File upload failed: ${uploadResult.error}`);
        }

        const remoteFilePath = uploadResult.remote_path;

        // Step 2: Run atomic tests using the uploaded schedule
        console.log('Step 2: Running atomic tests...');

        const atomicResponse = await fetch('/api/run-atomic', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            kali: {
              host: this.serverConfig.ipAddress,
              user: this.serverConfig.username,
              password: this.serverConfig.password,
              port: parseInt(this.serverConfig.port) || 22
            },
            target: {
              host: this.targetConfig.ipAddress,
              user: this.targetConfig.username,
              password: this.targetConfig.password
            },
            local_schedule_on_kali: remoteFilePath,
            auth: "ntlm",
            use_ssl: false,
            winrm_port: 5985,
            timeout: 1800
          })
        });

        console.log('Atomic test response status:', atomicResponse.status);

        if (!atomicResponse.ok) {
          throw new Error(`HTTP ${atomicResponse.status}: ${atomicResponse.statusText}`);
        }

        const result = await atomicResponse.json();
        console.log('Atomic test result:', result);

        if (result.status === 'success') {
          // Success
          alert(`Atomic test launched successfully!\n\nReturn Code: ${result.return_code}\n\nOutput:\n${result.stdout}\n${result.stderr ? '\nErrors:\n' + result.stderr : ''}`);
        } else {
          alert(`Atomic test failed.\n\nReturn Code: ${result.return_code}\nError: ${result.stderr || 'Unknown error'}`);
        }

      } catch (error: any) {
        console.error('Error launching atomic test:', error);
        alert(`Error launching atomic test: ${error.message || error}`);
      } finally {
        // Reset button state
        if (launchButton) {
          launchButton.textContent = originalText;
          launchButton.disabled = false;
        }
      }
    },

  },
  components: {
    Close,
    Tab,
    TabBox
  }
});
</script>

<style scoped>
.integration-tools-dialog-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  transition: opacity 0.3s ease-out;
}

.integration-tools-dialog-overlay.hidden {
  opacity: 0;
  pointer-events: none;
}

.integration-tools-dialog {
  background: #242424;
  border: 1px solid #303030;
  border-radius: 4px;
  width: 800px;
  height: 600px;
  display: flex;
  flex-direction: column;
  color: #d9d9d9;
}

.dialog-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid #303030;
  background: #2a2a2a;
}

.dialog-header h2 {
  margin: 0;
  font-size: 16px;
  font-weight: 500;
}

.close-button {
  cursor: pointer;
  padding: 4px;
  border-radius: 2px;
}

.close-button:hover {
  background: #383838;
}

.dialog-content {
  flex: 1;
  overflow: hidden;
}

.tab-content {
  padding: 20px;
  height: 100%;
  box-sizing: border-box;
  overflow-y: auto;
  overflow-x: hidden;
}

/* Transparent scrollbar styling */
.tab-content::-webkit-scrollbar {
  width: 8px;
}

.tab-content::-webkit-scrollbar-track {
  background: transparent;
}

.tab-content::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.2);
  border-radius: 4px;
}

.tab-content::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.3);
}

.tab-header {
  margin-bottom: 24px;
}

.tab-header h2 {
  margin: 0 0 8px 0;
  font-size: 24px;
  font-weight: 500;
  color: #ffffff;
}

.description {
  margin: 0;
  color: #b0b0b0;
  font-size: 14px;
  line-height: 1.4;
}

.button-group {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.primary-button {
  background: #5a7db8;
  color: white;
  border: none;
  padding: 10px 20px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  transition: background-color 0.2s;
}

.primary-button:hover {
  background: #4a6da8;
}

.secondary-button {
  background: #3a3a3a;
  color: #d9d9d9;
  border: 1px solid #4a4a4a;
  padding: 10px 20px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  transition: all 0.2s;
}

.secondary-button:hover {
  background: #4a4a4a;
  border-color: #5a5a5a;
}

.features-section,
.options-section,
.status-section,
.tools-list-section {
  margin-top: 24px;
}

.features-section h3,
.options-section h3,
.tools-list-section h3 {
  margin: 0 0 12px 0;
  font-size: 16px;
  font-weight: 500;
  color: #ffffff;
}

.features-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.features-list li {
  color: #b0b0b0;
  padding: 4px 0;
  position: relative;
  padding-left: 20px;
}

.features-list li::before {
  content: "•";
  color: #5a7db8;
  position: absolute;
  left: 0;
  font-weight: bold;
}

.checkbox-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.checkbox-item {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: #d9d9d9;
  font-size: 14px;
}

.checkbox-item input[type="checkbox"] {
  width: 16px;
  height: 16px;
  accent-color: #5a7db8;
}

.status-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 16px;
  border-radius: 4px;
  font-size: 14px;
}

.status-indicator.disconnected {
  background: rgba(220, 38, 127, 0.1);
  border: 1px solid rgba(220, 38, 127, 0.3);
}

.status-label {
  color: #b0b0b0;
}

.status-value {
  color: #dc267f;
  font-weight: 500;
}

.empty-state {
  text-align: center;
  padding: 32px 20px;
  color: #888;
}

.empty-state p {
  margin: 4px 0;
}

.empty-hint {
  font-size: 12px;
  opacity: 0.7;
}

.config-sections-container {
  display: flex;
  gap: 24px;
  margin-top: 24px;
}

.server-config-section,
.target-host-section {
  flex: 1;
}

.server-config-section h3,
.target-host-section h3 {
  margin: 0 0 16px 0;
  font-size: 16px;
  font-weight: 500;
  color: #ffffff;
}

.form-row {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
}

.form-group {
  margin-bottom: 16px;
}

.inline-form-group {
  display: flex;
  align-items: center;
  margin-bottom: 12px;
  gap: 8px;
}

.inline-form-group label {
  font-size: 14px;
  font-weight: 500;
  color: #d9d9d9;
  min-width: 100px;
  flex-shrink: 0;
}

.inline-form-group input {
  flex: 1;
  max-width: 180px;
  padding: 8px 10px;
  background: #3a3a3a;
  border: 1px solid #4a4a4a;
  border-radius: 4px;
  color: #d9d9d9;
  font-size: 14px;
  box-sizing: border-box;
  transition: border-color 0.2s;
}

.inline-form-group input:focus {
  outline: none;
  border-color: #5a7db8;
}

.inline-form-group input::placeholder {
  color: #888;
}

.form-group label {
  display: block;
  margin-bottom: 6px;
  font-size: 14px;
  font-weight: 500;
  color: #d9d9d9;
}

.form-group input {
  width: 100%;
  padding: 10px 12px;
  background: #3a3a3a;
  border: 1px solid #4a4a4a;
  border-radius: 4px;
  color: #d9d9d9;
  font-size: 14px;
  box-sizing: border-box;
  transition: border-color 0.2s;
}

.form-group input:focus {
  outline: none;
  border-color: #5a7db8;
}

.form-group input::placeholder {
  color: #888;
}

.os-select {
  width: 100%;
  padding: 10px 12px;
  background: #3a3a3a;
  border: 1px solid #4a4a4a;
  border-radius: 4px;
  color: #d9d9d9;
  font-size: 14px;
  box-sizing: border-box;
  transition: border-color 0.2s;
  cursor: pointer;
}

.os-select:focus {
  outline: none;
  border-color: #5a7db8;
}

.os-select option {
  background: #3a3a3a;
  color: #d9d9d9;
  padding: 8px 12px;
}

.os-select-inline {
  flex: 1;
  max-width: 180px;
  padding: 8px 10px;
  background: #3a3a3a;
  border: 1px solid #4a4a4a;
  border-radius: 4px;
  color: #d9d9d9;
  font-size: 14px;
  box-sizing: border-box;
  transition: border-color 0.2s;
  cursor: pointer;
}

.os-select-inline:focus {
  outline: none;
  border-color: #5a7db8;
}

.os-select-inline option {
  background: #3a3a3a;
  color: #d9d9d9;
  padding: 8px 12px;
}

.launch-test-section {
  margin: 24px 0;
  text-align: center;
}

.launch-test-button {
  background: #5a7db8;
  color: white;
  border: none;
  padding: 12px 32px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 16px;
  font-weight: 500;
  transition: background-color 0.2s;
  min-width: 140px;
}

.launch-test-button:hover {
  background: #4a6da8;
}

.launch-test-button:active {
  background: #3a5d98;
}

.section-divider {
  border: none;
  border-top: 1px solid #404040;
  margin: 32px 0;
}

.schedule-file-section {
  margin-top: 24px;
}

.schedule-file-section h3 {
  margin: 0 0 8px 0;
  font-size: 16px;
  font-weight: 500;
  color: #ffffff;
}

.schedule-file-section .description {
  margin: 0 0 16px 0;
  color: #b0b0b0;
  font-size: 14px;
}

.file-upload-area {
  border: 2px dashed #4a4a4a;
  border-radius: 8px;
  padding: 24px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
  background: #2a2a2a;
}

.file-upload-area:hover {
  border-color: #5a7db8;
  background: #323232;
}

.file-upload-area.drag-over {
  border-color: #5a7db8;
  background: #323232;
}

.file-input {
  display: none;
}

.upload-placeholder {
  color: #888;
}

.upload-icon {
  font-size: 32px;
  display: block;
  margin-bottom: 12px;
}

.upload-placeholder p {
  margin: 0 0 4px 0;
  font-size: 14px;
  color: #d9d9d9;
}

.upload-placeholder small {
  color: #888;
  font-size: 12px;
}

.uploaded-file {
  display: flex;
  align-items: center;
  gap: 12px;
  text-align: left;
  padding: 12px;
  background: #3a3a3a;
  border-radius: 4px;
  position: relative;
}

.file-icon {
  font-size: 24px;
}

.file-info {
  flex: 1;
}

.file-name {
  margin: 0;
  font-size: 14px;
  color: #d9d9d9;
  word-break: break-all;
}

.file-size {
  color: #888;
  font-size: 12px;
}

.remove-file {
  background: none;
  border: none;
  color: #dc267f;
  cursor: pointer;
  font-size: 16px;
  padding: 4px;
  border-radius: 2px;
  transition: background-color 0.2s;
}

.remove-file:hover {
  background: rgba(220, 38, 127, 0.1);
}

.error-message {
  margin-top: 8px;
  color: #dc267f;
  font-size: 13px;
  padding: 8px 12px;
  background: rgba(220, 38, 127, 0.1);
  border: 1px solid rgba(220, 38, 127, 0.3);
  border-radius: 4px;
}
</style>