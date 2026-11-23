// T3rnel Sessions Page — Session listing + Memory tab
'use strict';

function sessionsPage() {
  return {
    tab: 'sessions',
    // -- Sessions state --
    sessions: [],
    searchFilter: '',
    loading: true,
    loadError: '',

    // -- Memory state --
    memAgentId: '',
    kvPairs: [],
    showAdd: false,
    newKey: '',
    newValue: '""',
    editingKey: null,
    editingValue: '',
    memLoading: false,
    memLoadError: '',

    // -- Sessions methods --
    async loadSessions() {
      this.loading = true;
      this.loadError = '';
      try {
        var data = await T3rnelAPI.get('/api/sessions');
        var sessions = data.sessions || [];
        var agents = Alpine.store('app').agents;
        var agentMap = {};
        agents.forEach(function(a) { agentMap[a.id] = a.name; });
        sessions.forEach(function(s) {
          s.agent_name = agentMap[s.agent_id] || '';
        });
        this.sessions = sessions;
      } catch(e) {
        this.sessions = [];
        this.loadError = e.message || 'Could not load sessions.';
      }
      this.loading = false;
    },

    async loadData() { return this.loadSessions(); },

    get filteredSessions() {
      var f = this.searchFilter.toLowerCase();
      if (!f) return this.sessions;
      return this.sessions.filter(function(s) {
        return (s.agent_name || '').toLowerCase().indexOf(f) !== -1 ||
               (s.agent_id || '').toLowerCase().indexOf(f) !== -1;
      });
    },

    openInChat(session) {
      var agents = Alpine.store('app').agents;
      var agent = agents.find(function(a) { return a.id === session.agent_id; });
      if (agent) {
        Alpine.store('app').pendingAgent = agent;
      }
      location.hash = 'agents';
    },

    deleteSession(sessionId) {
      var self = this;
      var t = window.i18n ? window.i18n.t.bind(window.i18n) : function(k) { return k; };
      T3rnelToast.confirm(
        t('sessions.delete_session') || 'Delete Session',
        t('sessions.delete_confirm') || 'This will permanently remove the session and its messages.',
        async function() {
          try {
            await T3rnelAPI.del('/api/sessions/' + sessionId);
            self.sessions = self.sessions.filter(function(s) { return s.session_id !== sessionId; });
            T3rnelToast.success('Session deleted');
          } catch(e) {
            T3rnelToast.error('Failed to delete session: ' + e.message);
          }
        }
      );
    },

    // -- Memory methods --
    async loadKv() {
      if (!this.memAgentId) { this.kvPairs = []; return; }
      this.memLoading = true;
      this.memLoadError = '';
      try {
        var data = await T3rnelAPI.get('/api/memory/agents/' + this.memAgentId + '/kv');
        this.kvPairs = data.kv_pairs || [];
      } catch(e) {
        this.kvPairs = [];
        this.memLoadError = e.message || 'Could not load memory data.';
      }
      this.memLoading = false;
    },

    async addKey() {
      if (!this.memAgentId || !this.newKey.trim()) return;
      var value;
      try { value = JSON.parse(this.newValue); } catch(e) { value = this.newValue; }
      try {
        await T3rnelAPI.put('/api/memory/agents/' + this.memAgentId + '/kv/' + encodeURIComponent(this.newKey), { value: value });
        this.showAdd = false;
        T3rnelToast.success('Key "' + this.newKey + '" saved');
        this.newKey = '';
        this.newValue = '""';
        await this.loadKv();
      } catch(e) {
        T3rnelToast.error('Failed to save key: ' + e.message);
      }
    },

    deleteKey(key) {
      var self = this;
      var t = window.i18n ? window.i18n.t.bind(window.i18n) : function(k) { return k; };
      T3rnelToast.confirm(
        t('sessions.delete_key') || 'Delete Key',
        (t('sessions.delete_key_confirm') || 'Delete key') + ' "' + key + '"? This cannot be undone.',
        async function() {
          try {
            await T3rnelAPI.del('/api/memory/agents/' + self.memAgentId + '/kv/' + encodeURIComponent(key));
            T3rnelToast.success('Key "' + key + '" deleted');
            await self.loadKv();
          } catch(e) {
            T3rnelToast.error('Failed to delete key: ' + e.message);
          }
        }
      );
    },

    startEdit(kv) {
      this.editingKey = kv.key;
      this.editingValue = typeof kv.value === 'object' ? JSON.stringify(kv.value, null, 2) : String(kv.value);
    },

    cancelEdit() {
      this.editingKey = null;
      this.editingValue = '';
    },

    async saveEdit() {
      if (!this.editingKey || !this.memAgentId) return;
      var value;
      try { value = JSON.parse(this.editingValue); } catch(e) { value = this.editingValue; }
      try {
        await T3rnelAPI.put('/api/memory/agents/' + this.memAgentId + '/kv/' + encodeURIComponent(this.editingKey), { value: value });
        T3rnelToast.success('Key "' + this.editingKey + '" updated');
        this.editingKey = null;
        this.editingValue = '';
        await this.loadKv();
      } catch(e) {
        T3rnelToast.error('Failed to save: ' + e.message);
      }
    }
  };
}
