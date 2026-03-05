ALTER TABLE `scan_findings` ADD `poc` json;--> statement-breakpoint
ALTER TABLE `scans` ADD `scenarios` json;--> statement-breakpoint
ALTER TABLE `scans` ADD `trendSummary` json;