import { useCallback, useState } from "react";
import { Upload } from "lucide-react";

interface FileUploadProps {
  onFileSelect: (file: File) => void;
  accept?: string;
  label?: string;
  description?: string;
}

export default function FileUpload({
  onFileSelect,
  accept = "*",
  label = "Upload File",
  description = "Drag and drop or click to browse",
}: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) {
        setFileName(file.name);
        onFileSelect(file);
      }
    },
    [onFileSelect]
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) {
        setFileName(file.name);
        onFileSelect(file);
      }
    },
    [onFileSelect]
  );

  return (
    <label
      className={`flex flex-col items-center justify-center w-full h-48 border-2 border-dashed rounded-xl cursor-pointer transition-colors ${
        isDragging
          ? "border-primary-500 bg-primary-500/10"
          : "border-dark-border hover:border-primary-500/50 bg-dark-card"
      }`}
      onDragOver={(e) => {
        e.preventDefault();
        setIsDragging(true);
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
    >
      <Upload className="w-10 h-10 text-gray-400 mb-3" />
      <p className="text-sm font-medium text-gray-300">{label}</p>
      <p className="text-xs text-gray-500 mt-1">{description}</p>
      {fileName && (
        <p className="text-xs text-primary-400 mt-2 font-mono">{fileName}</p>
      )}
      <input
        type="file"
        className="hidden"
        accept={accept}
        onChange={handleChange}
      />
    </label>
  );
}
