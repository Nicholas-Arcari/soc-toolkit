import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Bug, ExternalLink, Mail } from "lucide-react";

const DEV_EMAIL = "arcari.nicholas0@gmail.com";

// No SMTP infra needed (host-agnostic): the form composes a mailto: so the
// message opens in the user's own mail client. Direct email is offered too.
export default function Contact() {
  const { t } = useTranslation();
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    const s = encodeURIComponent(subject || t("contact.defaultSubject"));
    const b = encodeURIComponent(message);
    window.location.href = `mailto:${DEV_EMAIL}?subject=${s}&body=${b}`;
  }

  const fieldClasses =
    "w-full rounded-lg bg-background border border-border px-3 py-2 text-foreground placeholder-muted focus:outline-none focus:ring-2 focus:ring-emerald-500/60 focus:border-emerald-500";

  return (
    <div className="max-w-2xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground">
          {t("contact.title")}
        </h1>
        <p className="text-muted mt-2">{t("contact.subtitle")}</p>
      </div>

      <div className="bg-card border border-border rounded-xl p-6 space-y-5">
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-2">
            <label
              htmlFor="c-subject"
              className="block text-xs font-medium text-muted"
            >
              {t("contact.subject")}
            </label>
            <input
              id="c-subject"
              type="text"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder={t("contact.subjectPlaceholder")}
              className={fieldClasses}
            />
          </div>
          <div className="space-y-2">
            <label
              htmlFor="c-message"
              className="block text-xs font-medium text-muted"
            >
              {t("contact.message")}
            </label>
            <textarea
              id="c-message"
              rows={6}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder={t("contact.messagePlaceholder")}
              className={`${fieldClasses} resize-y`}
            />
          </div>
          <button
            type="submit"
            className="inline-flex items-center gap-2 rounded-lg bg-foreground text-background hover:opacity-90 text-sm font-medium px-4 py-2 transition-opacity"
          >
            <Mail className="w-4 h-4" />
            {t("contact.openInEmail")}
          </button>
        </form>

        <div className="pt-2 border-t border-border text-sm text-muted">
          <p className="flex flex-wrap items-center gap-2">
            <Bug className="w-4 h-4 text-amber-400" />
            {t("contact.preferDirect")}
            <a
              href={`mailto:${DEV_EMAIL}`}
              className="inline-flex items-center gap-1 text-foreground hover:underline"
            >
              {DEV_EMAIL}
              <ExternalLink className="w-3 h-3" />
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}
