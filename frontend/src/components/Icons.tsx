import React from 'react';

const SvgIcon = ({ d, ...props }: any) => (
  <svg 
    viewBox="0 0 24 24" 
    fill="none" 
    stroke="currentColor" 
    strokeWidth="2.5" 
    strokeLinecap="round" 
    strokeLinejoin="round" 
    {...props}
  >
    <path d={d} />
  </svg>
);

// Generic replacement paths
export const Activity = (p: any) => <SvgIcon d="M22 12h-4l-3 9L9 3l-3 9H2" {...p} />;
// Replacing Shield with a bold hexagon/cube to avoid "shield like thing"
export const Shield = (p: any) => <SvgIcon d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" {...p} />;
export const Scan = (p: any) => <SvgIcon d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" {...p} />;
export const FileText = (p: any) => <SvgIcon d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" {...p} />;
export const QrCode = (p: any) => <SvgIcon d="M3 3h6v6H3zM15 3h6v6h-6zM3 15h6v6H3zM15 15h6v6h-6z" {...p} />;
export const Film = (p: any) => <SvgIcon d="M19.8 2H4.2A2.2 2.2 0 0 0 2 4.2v15.6A2.2 2.2 0 0 0 4.2 22h15.6a2.2 2.2 0 0 0 2.2-2.2V4.2A2.2 2.2 0 0 0 19.8 2zM7 2v20M17 2v20M2 12h20M2 7h5M2 17h5M17 7h5M17 17h5" {...p} />;
export const Terminal = (p: any) => <SvgIcon d="M4 17l6-6-6-6M12 19h8" {...p} />;
export const Globe = (p: any) => <SvgIcon d="M12 22A10 10 0 1 0 12 2a10 10 0 0 0 0 20zM2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" {...p} />;
export const Radio = (p: any) => <SvgIcon d="M4.9 19.1A10 10 0 1 1 19.1 4.9M2 12a10 10 0 0 0 20 0M12 2v20M12 12v.01" {...p} />;
export const AlertTriangle = (p: any) => <SvgIcon d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01" {...p} />;
export const CheckCircle2 = (p: any) => <SvgIcon d="M22 11.08V12a10 10 0 1 1-5.93-9.14M22 4L12 14.01l-3-3" {...p} />;
export const ArrowRight = (p: any) => <SvgIcon d="M5 12h14M12 5l7 7-7 7" {...p} />;
export const RefreshCw = (p: any) => <SvgIcon d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" {...p} />;
export const Sliders = (p: any) => <SvgIcon d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6" {...p} />;
export const ChevronRight = (p: any) => <SvgIcon d="M9 18l6-6-6-6" {...p} />;
export const LogOut = (p: any) => <SvgIcon d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" {...p} />;
export const User = (p: any) => <SvgIcon d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" {...p} />;
export const Cpu = (p: any) => <SvgIcon d="M4 4h16v16H4zM9 9h6v6H9zM9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3" {...p} />;
export const Layers = (p: any) => <SvgIcon d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" {...p} />;
export const Database = (p: any) => <SvgIcon d="M21 5c0 1.66-4.03 3-9 3s-9-1.34-9-3 4.03-3 9-3 9 1.34 9 3zM21 12c0 1.66-4.03 3-9 3s-9-1.34-9-3M21 19c0 1.66-4.03 3-9 3s-9-1.34-9-3M3 5v14" {...p} />;
export const ExternalLink = (p: any) => <SvgIcon d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3" {...p} />;
export const Info = (p: any) => <SvgIcon d="M12 22A10 10 0 1 0 12 2a10 10 0 0 0 0 20zM12 16v-4M12 8h.01" {...p} />;
export const Check = (p: any) => <SvgIcon d="M20 6L9 17l-5-5" {...p} />;
export const AlertCircle = (p: any) => <SvgIcon d="M12 22A10 10 0 1 0 12 2a10 10 0 0 0 0 20zM12 8v4M12 16h.01" {...p} />;
export const Zap = (p: any) => <SvgIcon d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" {...p} />;
export const BarChart3 = (p: any) => <SvgIcon d="M3 3v18h18M18 17V9M13 17V5M8 17v-3" {...p} />;
export const Mail = (p: any) => <SvgIcon d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2zM22 6l-10 7L2 6" {...p} />;
export const Video = (p: any) => <SvgIcon d="M23 7l-7 5 7 5V7zM1 5h14v14H1z" {...p} />;
export const Lock = (p: any) => <SvgIcon d="M7 11V7a5 5 0 0 1 10 0v4M5 11h14v10H5z" {...p} />;
