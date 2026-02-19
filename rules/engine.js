// Attack detection engine — evaluates blocks/txs against registered rules
// and maintains a rolling window of recent blocks for comparative analysis.

(function () {
  const SEVERITY_ORDER = ['none', 'low', 'medium', 'high', 'critical'];

  const engine = {
    rules: [],
    recentBlocks: [],
    WINDOW_SIZE: 20,

    registerRule(rule) {
      this.rules.push(rule);
    },

    analyzeBlock(block, txs) {
      const blockMeta = {
        number: parseInt(block.number, 16),
        timestamp: parseInt(block.timestamp, 16),
        baseFeeWei: block.baseFeePerGas ? parseInt(block.baseFeePerGas, 16) : 0,
        gasUsed: block.gasUsed ? parseInt(block.gasUsed, 16) : 0,
        gasLimit: block.gasLimit ? parseInt(block.gasLimit, 16) : 0,
        txCount: txs.length,
      };

      const alerts = [];
      const flaggedTxHashes = new Set();

      for (const rule of this.rules) {
        try {
          const result = rule.analyze(blockMeta, txs, this.recentBlocks);
          if (result && result.triggered) {
            alerts.push({
              ruleId: rule.id,
              name: rule.name,
              severity: result.severity || rule.severity,
              category: rule.category,
              summary: result.summary,
              detail: result.detail,
              metrics: result.metrics || {},
            });
            if (result.flaggedTxHashes) {
              for (const hash of result.flaggedTxHashes) {
                flaggedTxHashes.add(hash);
              }
            }
          }
        } catch (e) {
          // Never let a rule crash the visualizer
          console.warn('[AttackEngine] rule error:', rule.id, e);
        }
      }

      // Determine worst severity across all alerts
      let maxSeverity = 'none';
      for (const alert of alerts) {
        if (SEVERITY_ORDER.indexOf(alert.severity) > SEVERITY_ORDER.indexOf(maxSeverity)) {
          maxSeverity = alert.severity;
        }
      }

      const analysis = { alerts, flaggedTxHashes, maxSeverity, blockMeta };

      // Rolling window
      this.recentBlocks.push({ ...blockMeta, analysis });
      if (this.recentBlocks.length > this.WINDOW_SIZE) {
        this.recentBlocks.shift();
      }

      return analysis;
    },

    reset() {
      this.recentBlocks = [];
    },

    getSeverityColor(severity, alpha) {
      switch (severity) {
        case 'low':      return 'rgba(255,200,0,' + (alpha || 1) + ')';
        case 'medium':   return 'rgba(255,140,0,' + (alpha || 1) + ')';
        case 'high':     return 'rgba(255,50,0,' + (alpha || 1) + ')';
        case 'critical': return 'rgba(255,0,0,' + (alpha || 1) + ')';
        default:         return 'rgba(0,0,0,0)';
      }
    },

    getSeverityLabel(severity) {
      switch (severity) {
        case 'low':      return 'LOW';
        case 'medium':   return 'MED';
        case 'high':     return 'HIGH';
        case 'critical': return 'CRIT';
        default:         return '';
      }
    },
  };

  window.AttackEngine = engine;
})();
