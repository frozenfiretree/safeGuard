interface LoadingSpinnerProps {
  size?: number;
  className?: string;
}

export default function LoadingSpinner({
  size = 40,
  className,
}: LoadingSpinnerProps) {
  return (
    <div
      className={className}
      style={{
        width: size,
        height: size,
        border: '3px solid rgba(0, 240, 255, 0.2)',
        borderTop: '3px solid #00f0ff',
        borderRadius: '50%',
        animation: 'spin 1s linear infinite',
      }}
    />
  );
}
