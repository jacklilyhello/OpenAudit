OpenAudit

OpenAudit is an open source content moderation and audit engine.

The goal of this project is to build a high performance, extensible content moderation system inspired by large-scale internet audit systems.

OpenAudit is NOT a simple sensitive-word API.

OpenAudit is a complete audit engine.

⸻

Core Features

Current and future features include:

* Keyword matching
* Regex matching
* Domain matching
* URL matching
* Simplified / Traditional Chinese conversion
* Lowercase normalization
* Full-width / Half-width normalization
* Symbol and whitespace interference removal
* Unicode homoglyph normalization
* Pinyin matching
* Homophone matching
* Risk scoring
* Batch audit
* Rule hot reload
* Admin dashboard
* AI moderation
* OCR moderation
* Image moderation

⸻

Tech Stack

Backend:

* Go
* Gin

Rule format:

* YAML (preferred)
* JSON (optional)

Frontend:

* HTML
* CSS
* Vanilla JavaScript

Storage:

* Local rule files
* No database in MVP

⸻

Rule Source

The project should be compatible with:

https://github.com/konsheng/Sensitive-lexicon

The directory structure and categories should be compatible whenever possible.

⸻

Project Philosophy

This project is:

* Fast
* Extensible
* Maintainable
* Transparent
* API-first

Avoid:

* Hardcoded rules
* Monolithic files
* Global mutable state
* Complex dependencies

⸻

Project Structure

OpenAudit/

cmd/

internal/

web/

data/

README.md

CODEX.md

⸻

Matching Pipeline

Input

↓

Normalizer

↓

Keyword Matcher

↓

Regex Matcher

↓

Domain Matcher

↓

Pinyin Matcher

↓

Homophone Matcher

↓

AI Checker

↓

Risk Scoring

↓

Response

⸻

Keyword Matching

Use:

Aho-Corasick

Requirements:

* High performance
* Multiple pattern matching
* Unicode support
* Return matched text and positions

⸻

Regex Matching

Use:

Go regexp

Requirements:

* Precompile all regex at startup
* Return matched text and positions
* Support hot reload

⸻

Domain Matching

Support:

example.com

www.example.com

a.b.example.com

Should NOT match:

fakeexample.com

Support:

* exact match
* suffix match

⸻

Normalization

Must support:

Simplified / Traditional Chinese

Example:

法輪功

↓

法轮功

⸻

Lowercase

Example:

ABC.COM

↓

abc.com

⸻

Full-width / Half-width

Example:

ａｂｃ．ｃｏｍ

↓

abc.com

⸻

Symbol interference

Example:

法-轮-功

法_轮_功

法轮功

↓

法轮功

⸻

Unicode homoglyph

Example:

аbc.com

↓

abc.com

Ｇoogle

↓

google

⸻

Risk Scoring

Risk levels:

high

medium

low

Default scores:

high = 90

medium = 60

low = 30

Action priority:

block

review

pass

⸻

API Design

Required APIs:

GET

/health

POST

/audit/text

POST

/audit/batch

POST

/audit/url

POST

/audit/domain

GET

/rules/stats

POST

/rules/reload

GET

/admin

⸻

Admin Dashboard

The admin page should provide:

* Service status
* Rule statistics
* Text testing
* Batch testing
* Risk score
* Match result display
* Rule reload button
* API health

No authentication in MVP.

⸻

AI Moderation

AI moderation must be abstracted.

Provide interface:

Checker

Do NOT tightly couple any provider.

Potential providers:

* OpenAI
* DeepSeek
* Gemini
* Qwen
* Claude

⸻

Development Rules

IMPORTANT:

Always read CODEX.md before starting work.

NEVER modify existing Development Log entries.

NEVER delete Development Log entries.

After finishing ANY task:

Append a new Development Log section.

Unless explicitly requested:

Do NOT rewrite history.

Only append.

⸻

Development Log

This section is append-only.

Never edit previous entries.

Append new entries only.

