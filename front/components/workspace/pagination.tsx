"use client";

import { Icon } from "@/components/icon";
import { pageWindow } from "@/components/workspace/findings-logic";

type Props = { total: number; page: number; pageSize: number; sizes: number[]; noun?: string; onPage: (page: number) => void; onPageSize: (size: number) => void };

/** A table footer: the visible range, a rows-per-page choice, and previous/next. */
export function Pagination({ total, page, pageSize, sizes, noun = "findings", onPage, onPageSize }: Props) {
  const window = pageWindow(total, page, pageSize);
  return (
    <div className="sheet-foot pager">
      <span className="pager-range num">{total ? `${window.from}–${window.to} of ${total}` : `0 ${noun}`}</span>
      <label className="pager-size">Rows per page
        <select className="select" value={pageSize} onChange={(event) => onPageSize(Number(event.target.value))}>{sizes.map((size) => <option key={size} value={size}>{size}</option>)}</select>
      </label>
      <nav className="pager-nav" aria-label="Pagination">
        <span className="num">Page {window.page} of {window.pages}</span>
        <button className="icon-btn" onClick={() => onPage(window.page - 1)} disabled={window.page <= 1} aria-label="Previous page"><Icon name="chevron-left" size={16}/></button>
        <button className="icon-btn" onClick={() => onPage(window.page + 1)} disabled={window.page >= window.pages} aria-label="Next page"><Icon name="chevron" size={16}/></button>
      </nav>
    </div>
  );
}
