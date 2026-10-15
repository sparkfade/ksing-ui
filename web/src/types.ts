export interface NodeInfo {
  server: string
  server_port: number
  method: string
  password: string
  udp_over_tcp?: boolean
  plugin?: string
  plugin_opts?: string
}

export interface TrafficStat {
  up: number
  down: number
}

export interface SubUrls {
  singbox?: string
  clash?: string
  v2ray?: string
}

export interface UserInfo {
  name: string
  enable: boolean
  password: string
  token: string
  note: string
  created_at: number
  has_panel_password: boolean
  link: string
  links?: string[]
  sub_url: string
  sub_urls?: SubUrls
  traffic?: TrafficStat
  servers?: string[]
  active?: boolean
  traffic_limit?: number
  expire_at?: number
  reset_day?: number
}

export interface ServerItem {
  sid: string
  name: string
  port: number
  reported_ip: string
  users: string[]
  note: string
  enabled: boolean
  created_at: number
  last_seen: number
  online: boolean
  agent_version: string
  last_error: string
  applied_hash: string
  desired_hash: string
  synced: boolean
  traffic?: TrafficStat
  domain: string
  cert_mode: '' | 'acme' | 'selfip' | 'unsafe'
  acme_email: string
  cert_not_after: number
  cert_issuer: string
}

export interface ServerCreated {
  sid: string
  token: string
  install_command: string
}

export interface ServerConfigPreview {
  hash: string
  config: Record<string, unknown>
  rulesets: unknown[]
}

export interface RateStat {
  rate_up: number
  rate_down: number
}

export interface TrafficData {
  users: Record<string, TrafficStat>
  servers: Record<string, TrafficStat & { users?: Record<string, TrafficStat> }>
  rates?: {
    total: RateStat
    servers: Record<string, RateStat>
  }
}

export interface SystemInfo {
  cpu: number
  mem: { total: number; used: number; percent: number }
  disk: { total: number; used: number; percent: number }
  load: [number, number, number]
  uptime: number
}

export interface CertItem {
  sid: string
  name: string
  domain: string
  cert_mode: '' | 'acme' | 'selfip' | 'unsafe'
  issuer: string
  not_after: number
  days_left: number | null
  status: 'pending' | 'ok' | 'expiring' | 'expired'
  online: boolean
}

export interface RouteRule {
  rule_set?: string[]
  domain?: string[]
  domain_suffix?: string[]
  domain_keyword?: string[]
  domain_regex?: string[]
  ip_cidr?: string[]
  port?: number[]
  users?: string[]
  nodes?: string[]
  action: 'route' | 'reject'
  outbound?: string
  dns?: string
}

export interface RoutesData {
  rules: RouteRule[]
  final: string | null
  user_final: Record<string, string>
  effective_final: string
}

export interface StatusData {
  counts: { users: number; nodes: number; servers: number; servers_online: number; rules: number; rulesets: number }
  server: { host: string; sni: string; panel_port: number }
}

export interface RulesetItem {
  tag: string
  source: string
  url: string
  path: string
}

export interface RulesetSource {
  key: string
  desc: string
  optional: boolean
}

export interface Settings {
  final: string
  host: string
  sni: string
  private_action: string
  auto_detect_interface: boolean
  log_level: string
  panel_listen: string
  panel_port: number
  sub_host: string
  sub_path: string
  sub_port?: number
  admin_user: string
}

export interface MeInfo extends UserInfo {
  exit: string
  my_rules: number
  server_port: number
  sni: string
}

export const SS_METHODS = [
  '2022-blake3-aes-128-gcm',
  '2022-blake3-aes-256-gcm',
  '2022-blake3-chacha20-poly1305',
  'none',
  'aes-128-gcm',
  'aes-192-gcm',
  'aes-256-gcm',
  'chacha20-ietf-poly1305',
  'xchacha20-ietf-poly1305',
  'aes-128-ctr',
  'aes-192-ctr',
  'aes-256-ctr',
  'aes-128-cfb',
  'aes-192-cfb',
  'aes-256-cfb',
  'rc4-md5',
  'chacha20-ietf',
  'xchacha20',
]

export const LOG_LEVELS = ['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic']
