/* eslint-disable no-unused-vars */

export interface Oauth extends User { };

declare global {
  namespace Express {
    interface User {
      id: number;
      name: string | null;
      email: string;
      provider: string;
      provider_id: string;
    }
  }
}
