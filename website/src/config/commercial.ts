/**
 * Public commercial framework derived from the current business model.
 * Prices describe the intended paid product ladder; paid capabilities are only
 * charged once the corresponding commercial features are actually activated.
 */
export const COMMERCIAL = {
  community: {
    name: 'Community',
    price: '$0',
    cadence: 'forever for the open-source core',
    eyebrow: 'AVAILABLE NOW',
    summary: 'For individual developers and open-source work using Aegis locally.',
    features: [
      'VS Code extension',
      'CLI + local backend',
      'Local evidence workflow',
      'Basic local verification',
      'Apache-2.0 source',
    ],
    cta: 'Install Aegis',
  },
  pro: {
    name: 'Founding Pro',
    price: '$19',
    cadence: 'per month · founding cohort',
    eyebrow: 'EARLY ACCESS',
    standardPrice: '$29/month standard Pro price',
    summary: 'For professional AI-heavy developers who want the first managed Aegis workflows as they become available.',
    features: [
      'Everything in Community',
      'Founding access to paid Pro capabilities',
      'Managed verification allowance when enabled',
      'Direct founding-user feedback channel',
      'Founding price protected for 24 months',
    ],
    cta: 'Request founding access',
  },
  teams: {
    name: 'Team',
    price: '$39',
    cadence: 'per active contributor / month',
    eyebrow: 'EARLY ACCESS',
    summary: 'For engineering teams that need shared verification, pull-request policy, and evidence workflows.',
    features: [
      'Everything in Pro',
      'Shared evidence and policy workflows',
      'Pull-request verification',
      'Team-scoped history and collaboration as shipped',
      '5-seat planned minimum',
    ],
    cta: 'Talk to us about Team',
  },
  enterprise: {
    name: 'Enterprise',
    price: 'Custom',
    cadence: 'annual agreement',
    eyebrow: 'SELECTIVE',
    summary: 'For organizations evaluating private deployment, organization controls, and deeper security integrations.',
    features: [
      'Private or hybrid deployment discussion',
      'Organization policy and governance scope',
      'Security and data-boundary review',
      'Enterprise integrations as contracted',
      'Support and commercial terms scoped in writing',
    ],
    cta: 'Contact Aegis',
  },
} as const;
