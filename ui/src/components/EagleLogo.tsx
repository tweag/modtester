export default function EagleLogo({ className = "w-12 h-12" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 200 180"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      {/* Left wing */}
      <path
        d="M88 70C80 55 65 40 45 32C30 26 15 28 8 35C3 42 5 52 12 60
           C20 68 32 72 42 74C35 65 30 55 32 46C36 38 48 36 58 42
           C65 46 72 54 78 64L88 70Z"
        fill="currentColor"
        opacity="0.95"
      />
      <path
        d="M78 80C68 68 52 52 35 44C22 38 10 42 6 50C3 58 8 66 18 72
           C28 77 40 78 50 78C42 72 36 64 38 56C42 50 52 48 62 54
           C68 58 74 66 78 74L78 80Z"
        fill="currentColor"
        opacity="0.85"
      />
      <path
        d="M80 95C70 85 55 72 38 66C26 62 16 66 13 73C10 80 15 88 24 92
           C33 96 44 95 52 93C46 88 42 82 44 75C47 70 56 68 64 72
           C70 76 76 84 80 92L80 95Z"
        fill="currentColor"
        opacity="0.75"
      />
      {/* Wing feather lines - left */}
      <path d="M15 42L35 48" stroke="currentColor" strokeWidth="1" opacity="0.3" strokeLinecap="round" />
      <path d="M10 55L32 58" stroke="currentColor" strokeWidth="1" opacity="0.3" strokeLinecap="round" />
      <path d="M18 70L38 70" stroke="currentColor" strokeWidth="1" opacity="0.3" strokeLinecap="round" />
      <path d="M20 82L40 80" stroke="currentColor" strokeWidth="1" opacity="0.3" strokeLinecap="round" />

      {/* Right wing (mirrored) */}
      <path
        d="M112 70C120 55 135 40 155 32C170 26 185 28 192 35C197 42 195 52 188 60
           C180 68 168 72 158 74C165 65 170 55 168 46C164 38 152 36 142 42
           C135 46 128 54 122 64L112 70Z"
        fill="currentColor"
        opacity="0.95"
      />
      <path
        d="M122 80C132 68 148 52 165 44C178 38 190 42 194 50C197 58 192 66 182 72
           C172 77 160 78 150 78C158 72 164 64 162 56C158 50 148 48 138 54
           C132 58 126 66 122 74L122 80Z"
        fill="currentColor"
        opacity="0.85"
      />
      <path
        d="M120 95C130 85 145 72 162 66C174 62 184 66 187 73C190 80 185 88 176 92
           C167 96 156 95 148 93C154 88 158 82 156 75C153 70 144 68 136 72
           C130 76 124 84 120 92L120 95Z"
        fill="currentColor"
        opacity="0.75"
      />
      {/* Wing feather lines - right */}
      <path d="M185 42L165 48" stroke="currentColor" strokeWidth="1" opacity="0.3" strokeLinecap="round" />
      <path d="M190 55L168 58" stroke="currentColor" strokeWidth="1" opacity="0.3" strokeLinecap="round" />
      <path d="M182 70L162 70" stroke="currentColor" strokeWidth="1" opacity="0.3" strokeLinecap="round" />
      <path d="M180 82L160 80" stroke="currentColor" strokeWidth="1" opacity="0.3" strokeLinecap="round" />

      {/* Shield */}
      <path
        d="M100 45L78 55L78 90C78 115 100 140 100 140C100 140 122 115 122 90L122 55L100 45Z"
        fill="currentColor"
        opacity="0.15"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinejoin="round"
      />
      {/* Shield inner border */}
      <path
        d="M100 52L83 60L83 88C83 110 100 132 100 132C100 132 117 110 117 88L117 60L100 52Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        opacity="0.4"
        strokeLinejoin="round"
      />
      {/* Shield checkmark / lock icon */}
      <path
        d="M92 88L98 96L110 78"
        stroke="currentColor"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity="0.9"
      />
      {/* Small keyhole accent on shield */}
      <circle cx="100" cy="72" r="4" fill="currentColor" opacity="0.5" />
      <path d="M100 76L100 82" stroke="currentColor" strokeWidth="2.5" opacity="0.5" strokeLinecap="round" />
    </svg>
  );
}
