export interface SecurityEvent {
  timestamp: number
  category: 'process' | 'network' | 'file'
  event_type: string
  pid: number
  ppid: number
  uid: number
  gid: number
  comm: string
  container_id: string
  container_name: string
  filename?: string
  old_filename?: string
  exit_code?: number
  mode?: number
  flags?: number
  old_uid?: number
  src_addr?: string
  dst_addr?: string
  src_port?: number
  dst_port?: number
  protocol?: number
  write_bytes?: number
}

export interface EventStats {
  total_events: number
  events_per_sec: number
  by_category: Record<string, number>
  by_type: Record<string, number>
  connected_clients: number
  last_event_time: string
}

export type EventCategory = 'process' | 'network' | 'file'

export const EVENT_TYPE_LABELS: Record<string, string> = {
  process_create: '进程创建', process_exit: '进程退出', privilege_escalation: '权限提升',
  tcp_connect: 'TCP连接', tcp_accept: 'TCP接受', tcp_close: 'TCP关闭',
  udp_send: 'UDP发送', udp_recv: 'UDP接收',
  file_create: '文件创建', file_modify: '文件修改', file_delete: '文件删除',
  file_rename: '文件重命名', file_chmod: '权限修改', file_chown: '所有者修改',
}

export const CATEGORY_COLORS: Record<string, string> = {
  process: '#3b82f6', network: '#10b981', file: '#f59e0b',
}

export const EVENT_TYPE_COLORS: Record<string, string> = {
  privilege_escalation: '#ef4444', process_create: '#3b82f6', process_exit: '#6366f1',
  tcp_connect: '#10b981', tcp_accept: '#059669', tcp_close: '#6b7280',
  udp_send: '#14b8a6', udp_recv: '#0d9488',
  file_create: '#f59e0b', file_modify: '#d97706', file_delete: '#dc2626',
  file_rename: '#8b5cf6', file_chmod: '#ec4899', file_chown: '#f97316',
}
