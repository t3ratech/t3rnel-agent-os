// T3rnel Workflows Page — Workflow builder + run history
'use strict';

function workflowsPage() {
  return {
    // -- Workflows state --
    workflows: [],
    showCreateModal: false,
    runModal: null,
    runInput: '',
    runResult: '',
    running: false,
    loading: true,
    loadError: '',
    newWf: { name: '', description: '', steps: [{ name: '', agent_name: '', mode: 'sequential', prompt: '{{input}}' }] },
    editModal: null,
    editWf: { name: '', description: '', steps: [] },
    stoppingId: null,
    _pollTimer: null,

    // -- Workflows methods --
    async loadWorkflows() {
      this.loading = true;
      this.loadError = '';
      try {
        this.workflows = await T3rnelAPI.get('/api/workflows');
      } catch(e) {
        this.workflows = [];
        this.loadError = e.message || 'Could not load workflows.';
      }
      this.loading = false;
    },

    async loadData() {
      await this.loadWorkflows();
      this.startStatusPolling();
    },

    // -- Run status (ISSUE-007) --

    // Refresh the list while any workflow is running so the pill and the
    // Start/Stop control reflect live state instead of the page-load snapshot.
    startStatusPolling() {
      var self = this;
      if (this._pollTimer) return;
      this._pollTimer = setInterval(function() {
        var anyRunning = self.workflows.some(function(w) { return w.status === 'running'; });
        if (anyRunning || self.stoppingId) self.loadWorkflows();
      }, 3000);
    },

    statusLabel(wf) {
      if (wf.status === 'running') return 'Running';
      if (!wf.last_run_state) return 'Idle';
      var s = wf.last_run_state;
      return s.charAt(0).toUpperCase() + s.slice(1);
    },

    statusClass(wf) {
      if (wf.status === 'running') return 'badge-info';
      switch (wf.last_run_state) {
        case 'completed': return 'badge-success';
        case 'failed':    return 'badge-danger';
        case 'cancelled': return 'badge-warning';
        default:          return 'badge-muted';
      }
    },

    statusDetail(wf) {
      if (wf.status === 'running' && wf.active_run_started_at) {
        return 'since ' + new Date(wf.active_run_started_at).toLocaleTimeString();
      }
      if (wf.last_run_error) return String(wf.last_run_error).slice(0, 80);
      if (wf.last_run_completed_at) {
        return 'last ' + new Date(wf.last_run_completed_at).toLocaleString();
      }
      return 'never run';
    },

    async stopWorkflow(wf) {
      this.stoppingId = wf.id;
      try {
        var res = await T3rnelAPI.post('/api/workflows/' + wf.id + '/stop', {});
        if (res.status === 'stopping') {
          T3rnelToast.success('Stopping workflow — it will halt at the next step boundary.');
        } else if (res.status === 'idle') {
          T3rnelToast.info('Workflow is not running.');
        }
        await this.loadWorkflows();
      } catch(e) {
        T3rnelToast.error('Could not stop workflow: ' + (e.message || 'unknown error'));
      }
      this.stoppingId = null;
    },

    async createWorkflow() {
      var steps = this.newWf.steps.map(function(s) {
        return { name: s.name || 'step', agent_name: s.agent_name, mode: s.mode, prompt: s.prompt || '{{input}}' };
      });
      try {
        var wfName = this.newWf.name;
        await T3rnelAPI.post('/api/workflows', { name: wfName, description: this.newWf.description, steps: steps });
        this.showCreateModal = false;
        this.newWf = { name: '', description: '', steps: [{ name: '', agent_name: '', mode: 'sequential', prompt: '{{input}}' }] };
        T3rnelToast.success('Workflow "' + wfName + '" created');
        await this.loadWorkflows();
      } catch(e) {
        T3rnelToast.error('Failed to create workflow: ' + e.message);
      }
    },

    showRunModal(wf) {
      this.runModal = wf;
      this.runInput = '';
      this.runResult = '';
    },

    async executeWorkflow() {
      if (!this.runModal) return;
      this.running = true;
      this.runResult = '';
      try {
        var res = await T3rnelAPI.post('/api/workflows/' + this.runModal.id + '/run', { input: this.runInput });
        this.runResult = res.output || JSON.stringify(res, null, 2);
        T3rnelToast.success('Workflow completed');
      } catch(e) {
        this.runResult = 'Error: ' + e.message;
        T3rnelToast.error('Workflow failed: ' + e.message);
      }
      this.running = false;
      await this.loadWorkflows();
    },

    async viewRuns(wf) {
      try {
        var runs = await T3rnelAPI.get('/api/workflows/' + wf.id + '/runs');
        this.runResult = JSON.stringify(runs, null, 2);
        this.runModal = wf;
      } catch(e) {
        T3rnelToast.error('Failed to load run history: ' + e.message);
      }
    },

    async deleteWorkflow(wf) {
      if (!confirm('Delete workflow "' + wf.name + '"? This cannot be undone.')) return;
      try {
        await T3rnelAPI.delete('/api/workflows/' + wf.id);
        T3rnelToast.success('Workflow "' + wf.name + '" deleted');
        await this.loadWorkflows();
      } catch(e) {
        T3rnelToast.error('Failed to delete workflow: ' + e.message);
      }
    },

    async showEditModal(wf) {
      try {
        var full = await T3rnelAPI.get('/api/workflows/' + wf.id);
        this.editWf = {
          name: full.name || '',
          description: full.description || '',
          steps: (full.steps || []).map(function(s) {
            return {
              name: s.name || '',
              agent_name: (s.agent && s.agent.name) || '',
              mode: s.mode || 'sequential',
              prompt: s.prompt_template || '{{input}}'
            };
          })
        };
        if (this.editWf.steps.length === 0) {
          this.editWf.steps.push({ name: '', agent_name: '', mode: 'sequential', prompt: '{{input}}' });
        }
        this.editModal = wf;
      } catch(e) {
        T3rnelToast.error('Failed to load workflow: ' + e.message);
      }
    },

    async saveWorkflow() {
      if (!this.editModal) return;
      var steps = this.editWf.steps.map(function(s) {
        return { name: s.name || 'step', agent_name: s.agent_name, mode: s.mode, prompt: s.prompt || '{{input}}' };
      });
      try {
        var wfName = this.editWf.name;
        await T3rnelAPI.put('/api/workflows/' + this.editModal.id, { name: wfName, description: this.editWf.description, steps: steps });
        this.editModal = null;
        T3rnelToast.success('Workflow "' + wfName + '" updated');
        await this.loadWorkflows();
      } catch(e) {
        T3rnelToast.error('Failed to update workflow: ' + e.message);
      }
    }
  };
}
