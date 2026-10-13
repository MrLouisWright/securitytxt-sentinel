import type { Report, PolicyOptions, RuleInfo, Severity } from './core.js';
export * from './core.js';
export interface RawFinding { rule: string; location?: string; line?: number; message: string; severity?: Severity; evidence?: string; fix?: string; }
export interface SecurityTxtField { name: string; rawName: string; value: string; line: number; }
export interface ParsedSecurityTxt { fields: SecurityTxtField[]; bad: Array<{ line: number; text: string }>; signature: { signed: boolean; complete: boolean }; }
export interface ParsedRobots { groups: Array<{ agents: string[]; rules: Array<{ type: 'allow' | 'disallow'; path: string; line: number }>; line: number }>; sitemaps: Array<{ value: string; line: number }>; bad: Array<{ line: number; text: string }>; early: Array<{ line: number; text: string }>; }
export interface FetchResult { status?: number; url?: string; chain: string[]; contentType?: string; body?: string; error?: string; }
export interface CheckOptions extends PolicyOptions { robots?: boolean; kind?: 'security' | 'robots'; canonicalUrl?: string; warnDays?: number; timeout?: number; concurrency?: number; fetch?: (url: string, opts: object) => Promise<FetchResult>; }
export declare const VERSION: string;
export declare const RULES: Record<string, RuleInfo>;
export declare const TOOL: { name: string; version: string; rules: Record<string, RuleInfo>; title: string; emoji: string; defaultFailOn: Severity };
export declare function toOrigin(target: string): string;
export declare function parseSecurityTxt(text: string): ParsedSecurityTxt;
export declare function lintSecurityTxt(text: string, ctx?: { url?: string; file?: string; contentType?: string; now?: string | Date; warnDays?: number }): { raw: RawFinding[]; parsed: ParsedSecurityTxt };
export declare function parseRobots(text: string): ParsedRobots;
export declare function lintRobots(text: string, ctx?: { url?: string; file?: string }): { raw: RawFinding[]; parsed: ParsedRobots };
export declare function fetchText(url: string, opts?: { timeout?: number; userAgent?: string }): Promise<FetchResult>;
/** Check domains/URLs (fetched over HTTPS) and local security.txt / robots.txt files. */
export declare function check(targets: string[], opts?: CheckOptions): Promise<Report>;
