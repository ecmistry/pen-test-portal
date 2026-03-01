CREATE TABLE `reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scanId` int NOT NULL,
	`userId` int NOT NULL,
	`title` varchar(500) NOT NULL,
	`executiveSummary` text,
	`markdownContent` text,
	`jsonContent` json,
	`complianceNotes` text,
	`generatedAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `reports_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scan_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scanId` int NOT NULL,
	`category` varchar(100) NOT NULL,
	`severity` enum('critical','high','medium','low','info') NOT NULL,
	`title` varchar(500) NOT NULL,
	`description` text,
	`evidence` text,
	`recommendation` text,
	`cweId` varchar(20),
	`owaspCategory` varchar(100),
	`status` enum('open','acknowledged','resolved','false_positive') NOT NULL DEFAULT 'open',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scan_findings_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scan_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scanId` int NOT NULL,
	`level` enum('info','warn','error','success','debug') NOT NULL DEFAULT 'info',
	`message` text NOT NULL,
	`phase` varchar(100),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scan_logs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`targetId` int NOT NULL,
	`userId` int NOT NULL,
	`status` enum('queued','running','completed','failed','cancelled') NOT NULL DEFAULT 'queued',
	`tools` varchar(500) NOT NULL DEFAULT 'headers,auth,sqli,xss',
	`securityScore` int,
	`riskLevel` enum('critical','high','medium','low','info'),
	`totalFindings` int DEFAULT 0,
	`criticalCount` int DEFAULT 0,
	`highCount` int DEFAULT 0,
	`mediumCount` int DEFAULT 0,
	`lowCount` int DEFAULT 0,
	`infoCount` int DEFAULT 0,
	`startedAt` timestamp,
	`completedAt` timestamp,
	`errorMessage` text,
	`triggeredBy` enum('manual','schedule') NOT NULL DEFAULT 'manual',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scans_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `schedules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`targetId` int NOT NULL,
	`userId` int NOT NULL,
	`cronExpression` varchar(100) NOT NULL,
	`tools` varchar(500) NOT NULL DEFAULT 'headers,auth,sqli,xss',
	`enabled` boolean NOT NULL DEFAULT true,
	`lastRunAt` timestamp,
	`nextRunAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `schedules_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `targets` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`name` varchar(255) NOT NULL,
	`url` varchar(2048) NOT NULL,
	`description` text,
	`tags` varchar(500),
	`scanFrequency` enum('manual','daily','weekly','monthly') NOT NULL DEFAULT 'manual',
	`isActive` boolean NOT NULL DEFAULT true,
	`lastScannedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `targets_id` PRIMARY KEY(`id`)
);
