<img width="828" height="309" alt="image" src="https://github.com/user-attachments/assets/bae096d5-a0db-46cd-aa0f-4ef7cee11371" />

## Part 2 - Threat Hunt Brief

### **[ORG] // the clinic grew fast, and one new starter was easier to find than anyone realized**
<img width="821" height="176" alt="image" src="https://github.com/user-attachments/assets/543d9907-3253-4598-b046-e68b61643290" />

---
### **REVIEW BRIEF**

**REVIEW ASSIGNMENT // [ORG SOC]**

**From:** Hunt Lead // [ORG SOC]
**To:** DCormier // on shift
**Re:** ORG // credential exposure follow-up
You know this client. Nimbus Health, the outpatient clinic we picked apart back in March. They are back on the board, and this time the shape of the problem is different.

A nearby industrial park opened. Patient volume went up, and so did billing, HR onboarding and endpoint support. Nimbus hired across every department at once and put the new starters on the same shared workstations they already had. Growth first, access review later.

During a routine credential exposure sweep we flagged one of those new hires. His identity is sitting in public, and so is an old password of his. In the same period, authentication telemetry on one of their machines shows failed logons against that account, then a success.

What we need you to work out:

   - How the account was found and why it was worth targeting
   - Whether the credentials were actually used, and from where
   - What happened once someone was on the keyboard
   - What the account reached outside its role, and where that material went
   - Whether anything was left behind, and the honest root cause

Two things to hold from the start. The loudest thing in the data is not the story. That box is under constant brute-force noise, and almost none of it goes anywhere. And not every deletion is a cover-up. Windows and its applications tidy up after themselves constantly. Learn to tell a machine apart from a person.

Get hunting.
**// Hunt Lead**
[ORG SOC] · [ORG] series, part two

---
### Investigation Report
[Investigation Report]()
