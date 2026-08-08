export const SITE = {
  name: 'Aegis',
  descriptor: 'Trust infrastructure for software agents',
  slogan: 'Security claims need proof.',
  github: 'https://github.com/lemkyz/Aegis',
  marketplace: 'https://marketplace.visualstudio.com/items?itemName=aegis-security.aegis-security',
  release: '0.2.0',
  contactEmail: import.meta.env.PUBLIC_CONTACT_EMAIL || 'hello@aegistrustlayer.com',
  securityEmail: import.meta.env.PUBLIC_SECURITY_EMAIL || 'security@aegistrustlayer.com',
  founderEmail: import.meta.env.PUBLIC_FOUNDER_EMAIL || 'founder@aegistrustlayer.com',
  partnershipsEmail: import.meta.env.PUBLIC_PARTNERSHIPS_EMAIL || 'partnerships@aegistrustlayer.com',
  billingEmail: import.meta.env.PUBLIC_BILLING_EMAIL || 'billing@aegistrustlayer.com',
  siteUrl: (import.meta.env.PUBLIC_SITE_URL || 'https://aegistrustlayer.com').replace(/\/$/, ''),
} as const;
