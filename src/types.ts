export interface Tenant {
  id: string;
  name: string;
  slug: string;
  created_at: number;
}

export interface User {
  id: string;
  tenant_id: string;
  username: string;
  client_secret: string;
  machine: boolean;
  admin: boolean;
  active: boolean;
  created_at: number;
  updated_at: number;
}

export interface Group {
  id: string;
  tenant_id: string;
  name: string;
  created_at: number;
}

export interface GroupMember {
  group_id: string;
  user_id: string;
}

export interface SigningKey {
  id: string;
  private_key: string;
  public_key: string;
  active: boolean;
  created_at: number;
}

export interface ScimTarget {
  id: string;
  tenant_id: string;
  name: string;
  url: string;
  token: string;
  active: boolean;
}
