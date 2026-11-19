import { cn } from "@/lib/utils"

interface RadialBackgroundProps {
  children?: React.ReactNode
  className?: string
}

export const RadialBackground = ({ children, className }: RadialBackgroundProps) => {
  return (
    <div className={cn("relative min-h-screen w-full overflow-hidden bg-white", className)}>
      <div className="absolute inset-0 -z-10 size-full bg-white [background:radial-gradient(125%_125%_at_50%_10%,#fff_40%,#63e_100%)]" />
      <div className="relative z-10">{children}</div>
    </div>
  )
}

