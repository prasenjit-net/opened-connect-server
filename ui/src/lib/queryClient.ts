import { QueryClient } from "@tanstack/react-query";

// Share server data across pages without refetching on every navigation.
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
});
