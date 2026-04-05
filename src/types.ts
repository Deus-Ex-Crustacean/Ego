export interface Workspace {
  id: string;
  name: string;
  client_secret: string;
  admin: boolean;
  active: boolean;
  created_at: number;
}

export interface User {
  id: string;
  username: string;
  client_secret: string;
  machine: boolean;
  active: boolean;
  created_at: number;
}

export interface SigningKey {
  id: string;
  private_key: string;
  public_key: string;
  active: boolean;
  created_at: number;
}
