import {
  Activity,
  Bell,
  Box,
  Bug,
  Cable,
  Container,
  Cpu,
  FileText,
  HardDrive,
  LayoutDashboard,
  Layers,
  Monitor,
  Network,
  Printer,
  Radar,
  Router,
  Server,
  Settings,
  ShieldAlert,
  Smartphone,
  Video,
  Waypoints,
  Wifi,
  Workflow,
  HelpCircle,
  type LucideIcon,
} from "lucide-react";

import type { AssetType } from "@/data/types";

export interface NavItem {
  id: string;
  label: string;
  path: string;
  icon: LucideIcon;
  description: string;
}

export interface NavGroup {
  label?: string;
  items: NavItem[];
}

export const navGroups: NavGroup[] = [
  {
    items: [{ id: "overview", label: "Overview", path: "/overview", icon: LayoutDashboard, description: "Posture at a glance" }],
  },
  {
    label: "Inventory",
    items: [
      { id: "assets", label: "Assets", path: "/assets", icon: Layers, description: "Discovered hosts and devices" },
      { id: "topology", label: "Topology", path: "/topology", icon: Waypoints, description: "Network graph and paths" },
    ],
  },
  {
    label: "Assess",
    items: [
      { id: "scans", label: "Scans", path: "/scans", icon: Radar, description: "Discovery and vulnerability jobs" },
      { id: "vulnerabilities", label: "Vulnerabilities", path: "/vulnerabilities", icon: Bug, description: "CVE index matched to inventory" },
      { id: "findings", label: "Findings", path: "/findings", icon: ShieldAlert, description: "Actionable issues per asset" },
    ],
  },
  {
    label: "Detect",
    items: [
      { id: "detections", label: "Detections", path: "/detections", icon: Bell, description: "Sensor and agent alerts" },
      { id: "events", label: "Events", path: "/events", icon: Activity, description: "Platform activity stream" },
    ],
  },
  {
    label: "Infrastructure",
    items: [
      { id: "connections", label: "Connections", path: "/connections", icon: Cable, description: "Connectors, endpoint devices and scanners" },
    ],
  },
  {
    items: [
      { id: "reports", label: "Reports", path: "/reports", icon: FileText, description: "Generated documents" },
      { id: "settings", label: "Settings", path: "/settings", icon: Settings, description: "Sites, users, feeds, audit" },
    ],
  },
];

export const navItems = navGroups.flatMap((g) => g.items);

export const assetTypeMeta: Record<AssetType, { label: string; icon: LucideIcon }> = {
  router: { label: "Router", icon: Router },
  switch: { label: "Switch", icon: Network },
  firewall: { label: "Firewall", icon: ShieldAlert },
  access_point: { label: "Access point", icon: Wifi },
  camera: { label: "Camera", icon: Video },
  server: { label: "Server", icon: Server },
  virtual_machine: { label: "Virtual machine", icon: Box },
  container_host: { label: "Container host", icon: Container },
  workstation: { label: "Workstation", icon: Monitor },
  printer: { label: "Printer", icon: Printer },
  iot: { label: "IoT / OT", icon: Video },
  nas: { label: "NAS", icon: HardDrive },
  mobile: { label: "Mobile", icon: Smartphone },
  hypervisor: { label: "Hypervisor", icon: Workflow },
  unknown: { label: "Unknown", icon: HelpCircle },
};
