export default function ProtocolErrorScreen({ message }: { message: string }) {
  return <section role="alert" className="card w-full max-w-[420px] p-8 text-center">
    <h1 className="text-xl font-semibold">This sign-in request can't be completed</h1>
    <p className="mt-3 text-sm text-ink-muted">{message}</p>
  </section>;
}
