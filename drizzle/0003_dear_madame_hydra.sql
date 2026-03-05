ALTER TABLE `scan_findings` ADD `cvssVector` varchar(200);--> statement-breakpoint
ALTER TABLE `scan_findings` ADD `cvssScore` decimal(3,1);--> statement-breakpoint
ALTER TABLE `scan_findings` ADD `remediationComplexity` varchar(20);--> statement-breakpoint
ALTER TABLE `scan_findings` ADD `remediationPriority` varchar(10);--> statement-breakpoint
ALTER TABLE `scan_findings` ADD `businessImpact` json;--> statement-breakpoint
ALTER TABLE `scan_findings` ADD `attackTechniques` json;--> statement-breakpoint
ALTER TABLE `scan_findings` ADD `iso27001Controls` json;