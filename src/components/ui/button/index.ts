import type { VariantProps } from "class-variance-authority"
import { cva } from "class-variance-authority"

export { default as Button } from "./Button.vue"

export const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-xl text-sm font-semibold transition-all duration-150 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-300 disabled:pointer-events-none disabled:opacity-50 active:scale-[0.985] active:translate-y-px [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default:
          "border border-blue-600 bg-blue-600 text-white shadow-[0_10px_24px_rgba(37,99,235,0.24)] hover:bg-blue-500 hover:border-blue-500",
        destructive:
          "border border-red-600 bg-red-600 text-white shadow-sm hover:bg-red-500 hover:border-red-500",
        outline:
          "border border-slate-200 bg-white text-slate-700 shadow-sm hover:bg-slate-50 hover:text-slate-950",
        secondary:
          "border border-slate-200 bg-slate-50 text-slate-800 shadow-sm hover:bg-slate-100",
        ghost: "text-slate-700 hover:bg-slate-100 hover:text-slate-950",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        "default": "h-10 px-4 py-2.5",
        "xs": "h-7 rounded px-2",
        "sm": "h-9 rounded-xl px-3 text-xs",
        "lg": "h-11 rounded-xl px-8",
        "icon": "h-10 w-10",
        "icon-sm": "size-8",
        "icon-lg": "size-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
)

export type ButtonVariants = VariantProps<typeof buttonVariants>
