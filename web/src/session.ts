import { useEffect, useState } from "react";
import * as api from "./api.js";
import type { Me } from "./api.js";

/**
 * One `GET /web/me` per page load, shared by every component that needs the
 * signed-in principal -- the header needs the email, the detail page needs
 * the principal_id to pass into the passkey ceremony. A rejected lookup
 * clears the cache so that signing in does not have to fight a memoized 401.
 */
let cached: Promise<Me> | null = null;

export function loadMe(): Promise<Me> {
  if (!cached) {
    cached = api.getMe().catch((err: unknown) => {
      cached = null;
      throw err;
    });
  }
  return cached;
}

export function clearMe(): void {
  cached = null;
}

export interface MeState {
  me: Me | null;
  error: unknown;
  loading: boolean;
}

export function useMe(enabled = true): MeState {
  const [state, setState] = useState<MeState>({
    me: null,
    error: null,
    loading: enabled,
  });

  useEffect(() => {
    if (!enabled) {
      setState({ me: null, error: null, loading: false });
      return;
    }
    let live = true;
    loadMe().then(
      (me) => live && setState({ me, error: null, loading: false }),
      (error: unknown) => live && setState({ me: null, error, loading: false }),
    );
    return () => {
      live = false;
    };
  }, [enabled]);

  return state;
}
