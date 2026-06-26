type AvatarProps = {
  username: string;
  avatar?: string | null;
  /** Rendered width/height in pixels. */
  size?: number;
  className?: string;
};

// Shows the uploaded profile image when present, otherwise a neutral
// initials chip. Kept tiny + presentational so the Sidebar and Profile
// page render avatars identically.
export default function Avatar({
  username,
  avatar,
  size = 36,
  className = "",
}: AvatarProps) {
  const dimension = { width: size, height: size };

  if (avatar) {
    return (
      <img
        src={avatar}
        alt={username}
        style={dimension}
        className={`shrink-0 rounded-full object-cover bg-card border border-border ${className}`}
      />
    );
  }

  return (
    <div
      style={dimension}
      aria-hidden
      className={`shrink-0 rounded-full bg-foreground/10 text-muted flex items-center justify-center font-semibold ${className}`}
    >
      <span style={{ fontSize: Math.round(size * 0.4) }}>
        {username.slice(0, 2).toUpperCase()}
      </span>
    </div>
  );
}
