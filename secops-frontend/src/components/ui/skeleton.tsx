import { cn } from "@/lib/utils"

function Skeleton({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-primary/10", className)}
      {...props}
    />
  )
}

function TableSkeleton({ rows = 5, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, r) => (
        <tr key={r} className="border-b border-border/50">
          {Array.from({ length: cols }).map((_, c) => (
            <td key={c} className="px-4 py-3">
              <Skeleton className={`h-4 ${c === 0 ? "w-40" : "w-20"}`} />
            </td>
          ))}
        </tr>
      ))}
    </>
  )
}

function ErrorState({ message, onRetry }: { message?: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
      <div className="w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center">
        <span className="text-destructive text-xl">!</span>
      </div>
      <p className="text-sm text-muted-foreground">{message ?? "Something went wrong"}</p>
      {onRetry && (
        <button onClick={onRetry} className="text-sm text-primary hover:underline">
          Try again
        </button>
      )}
    </div>
  )
}

function EmptyState({ icon, title, description }: { icon?: React.ReactNode; title: string; description?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
      {icon && <div className="text-muted-foreground/50">{icon}</div>}
      <p className="text-sm font-medium text-muted-foreground">{title}</p>
      {description && <p className="text-xs text-muted-foreground/70">{description}</p>}
    </div>
  )
}

export { Skeleton, TableSkeleton, ErrorState, EmptyState }
