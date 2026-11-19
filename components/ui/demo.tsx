import { DarkGradientBg } from "@/components/ui/elegant-dark-pattern"
import { RadialBackground } from "@/components/ui/light-theme-tailwind-css-background-snippet"

export function DarkDemo() {
  return (
    <DarkGradientBg>
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center space-y-6 p-8">
          <h1 className="text-4xl font-bold text-white">Dark Gradient Background</h1>
          <p className="text-lg text-gray-300 max-w-md">
            A clean, dark gradient background with subtle patterns, skewed cyan streaks, and textures.
          </p>
        </div>
      </div>
    </DarkGradientBg>
  )
}

export function LightDemo() {
  return (
    <RadialBackground>
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center space-y-6 p-8">
          <h1 className="text-4xl font-bold text-gray-900">Light Radial Background</h1>
          <p className="text-lg text-gray-600 max-w-md">
            A luminous, radiant light gradient background with purple/indigo flare.
          </p>
        </div>
      </div>
    </RadialBackground>
  )
}

export default function Home({ theme = "carbon" }: { theme?: "carbon" | "paper" }) {
  return theme === "carbon" ? <DarkDemo /> : <LightDemo />
}

