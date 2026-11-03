====================================================================
 DEPENDENCY-CHECK AUTOMATION - USER GUIDE
====================================================================
Scans the jars of one or more Java applications for known vulnerabilities
(OWASP dependency-check), after moving your own internal jars aside, and
produces three reports per application:

    [date][Project][AppCode][Env][dependency-check-report].html    raw scan
    [date][Project][AppCode][Env][dependency-check-analysis].ods   action list
    [date][Project][AppCode][Env][pentest-report].html             readable report


WHAT'S IN THIS FOLDER
--------------------------------------------------------------------
    START_HERE.txt             first use on a new machine; putting it on GitHub
    run_dependency_check.bat   double-click to run a scan
    setup_schedule.bat         run once to make it run itself on a schedule
    config\                    YOUR SETTINGS - config.txt (created on first run)
    apps\                      INPUT, if not listed in config - one folder per application
    reports\                   OUTPUT - reports\<application>\ (created as needed)
    work\                      scratch space the tool cleans up itself
    scripts\                   one-time setup: setup_venv.bat, setup_dependency_check.bat
    tools\                     dependency-check itself, once setup_dependency_check.bat put it there

Everything you ever edit is in config\. Back that folder up and you have
backed up your whole setup (settings, application list, AI prompt and the
AI answer cache).


ONE-TIME SETUP
--------------------------------------------------------------------
Setting the tool up on a new machine (or after a git clone) and putting
it on GitHub are described step by step in START_HERE.txt. In short:
Java 11+, scripts\setup_venv.bat (Python version only),
scripts\setup_dependency_check.bat, then NVD_API_KEY in config\config.txt.
The first scan downloads the NVD database (about 250 MB) and takes much
longer than the ones after it.

Upgrading to a newer version: unpack it over this folder. Your
config\config.txt, config\app_list.txt and config\prompt_template.txt are
never part of a package (it carries only their starting points, *.template
/ *.default), so they are kept as they are. Afterwards run
scripts\setup_venv.bat once, in case the new version needs newer packages.


THE USUAL SETUP: LIB FOLDERS IN CONFIG, SCANNED EVERY DAY BY ITSELF
--------------------------------------------------------------------
1. In config\config.txt list each application's lib folder:

       APP_FOLDERS=D:\QA\OrderService\lib, D:\QA\BillingApi\lib

   or one line per application (the lines add up):

       APP_FOLDERS=D:\QA\OrderService\lib
       APP_FOLDERS=D:\QA\BillingApi\lib

   Leave MODE=AUTO. A folder called lib is named after the folder above it
   (OrderService, BillingApi); write Name= in front to choose the name
   yourself:  APP_FOLDERS=Orders=D:\QA\OrderService\lib
   Quotes are optional. Jars in sub-folders count too.

2. Still in config.txt, set the cut-off time:

       SCHEDULE_ENABLED=yes
       SCHEDULE_FREQUENCY=DAILY
       SCHEDULE_TIME=22:00

3. Double-click setup_schedule.bat once. It prints the task's next run
   time. To see a run straight away:  schtasks /run /tn "<SCHEDULE_TASK_NAME>"

From then on the scan runs every day at that time on its own, also after a
reboot; if the PC was off or asleep at the cut-off time, the run starts as
soon as it is back. Reports land in reports\<application>\, and each run's
output is appended to reports\_logs\scheduled_runs.log.

These folders are never changed: their jars are copied to work\ and the
copy is scanned, so a running application is never disturbed. If a listed
folder is missing or holds no jars, the run reports it as NOT SCANNED and
fails (Task Scheduler's Last Run Result 0x1) - the other applications are
still scanned.

For many applications (10+) the list can go in config\app_list.txt
instead, one per line (examples are in that file):

    Payments=D:\QA\PaymentService\lib
    Inventory=D:\QA\InventoryService\lib


MANUAL USE WITH THE apps\ FOLDER
--------------------------------------------------------------------
When nothing is listed in APP_FOLDERS or app_list.txt, the tool scans
apps\ instead:

1. Inside apps\, create one folder per application, named anything, e.g.
       apps\OrderService\
       apps\BillingApi\
2. Put that application's jars inside its folder.
3. Double-click run_dependency_check.bat.
4. For each application it asks (press Enter to accept the default shown):
       Project Name
       Application Code
       Environment          (e.g. QA)
5. When it finishes, the reports are in reports\<application folder>\.

Before scanning, every internal jar - one matching a prefix in
INTERNAL_PACKAGES (e.g. com.example), recognised by its file name, by the
com/example/ classes inside it, or by its Maven groupId; any one is enough -
is moved into an internal_jars_<date> folder inside the application's folder
in apps\, so only third-party jars are scanned. Jars in sub-folders are handled
the same way. (Listed folders outside the tool's folder get the same
separation, but on a copy.)

Folders in apps\ whose name starts with _ are ignored, so you can park
sample data (e.g. apps\_samples\) without it being scanned every time.

Running the same application twice on one day never overwrites the first
run's reports - the second set gets a time suffix.

MODE=LIST scans only APP_FOLDERS and MODE=LIST_FILE only app_list.txt;
SCAN_MODE=LIVE_LIB makes the tool copy even the folders inside apps\
instead of moving their internal jars. The tool refuses to start if MODE or
SCAN_MODE holds anything else, so a typo can never make it move files.


AI-ASSISTED "RECOMMENDED VERSION" (OPTIONAL)
--------------------------------------------------------------------
Off by default: the reports still carry every CVE, and you fill in the
Recommended Version column yourself.

To turn it on, set ENABLE_AI=yes in config\config.txt and put your own key
in OPENAI_API_KEY. For every vulnerable dependency the tool then asks OpenAI
for the latest version that fixes its CVEs.

Answers are cached in config\ai_recommendation_cache.json and never asked
again for the same groupId:artifactId:version. A failed lookup (wrong key,
no network) is shown in that run's report but NOT cached, so it is retried
next time. If the cache file ever gets damaged, the tool sets it aside as
ai_recommendation_cache.corrupt-<date>.json instead of overwriting it.

The instructions sent to the AI are in config\prompt_template.txt - edit
them in Notepad, no code change needed.


EMAILING THE REPORTS (OPTIONAL)
--------------------------------------------------------------------
Set EMAIL_ENABLED=yes and fill in EMAIL_RECIPIENTS (separated by , or ;)
and SMTP_SERVER (ask your mail/infra team for the internal relay). Each
application's three reports are then emailed as soon as they are written;
extra OUTPUT_FORMAT files stay in reports\ only, to keep the email small. A failed send only prints a
warning - the reports are on disk either way. The mail server's certificate
is verified; see the SMTP_* notes in config.txt for ports 587/465/25.


MORE ABOUT THE SCHEDULE
--------------------------------------------------------------------
SCHEDULE_FREQUENCY can be DAILY, WEEKLY, MONTHLY or YEARLY (with
SCHEDULE_WEEKLY_DAY / SCHEDULE_MONTHLY_DAY / SCHEDULE_YEARLY_* next to it
in config.txt). Run setup_schedule.bat again after changing any SCHEDULE_*
value. To stop the schedule, set SCHEDULE_ENABLED=no and run
setup_schedule.bat again - it removes the task.

A scheduled run asks nothing: Project Name = the application's name,
Environment = DEFAULT_ENVIRONMENT, Application Code = SCHEDULE_APP_CODE (or
derived from the application's name). In Task Scheduler, "Last Run Result"
shows 0x1 if any application failed or could not be scanned.

By default the task runs as the user who registered it, while that user is
logged on (a locked screen is fine). For an unattended server set
SCHEDULE_RUN_AS_SYSTEM=yes so it runs with nobody logged on: register it by
right-clicking setup_schedule.bat > Run as administrator. SYSTEM cannot read
network shares, so the lib folders must be on that machine.

Two copies of the tool on one machine (QA and PROD, say) each need their own
SCHEDULE_TASK_NAME; setup refuses to replace a task that runs another copy.


TROUBLESHOOTING
--------------------------------------------------------------------
"First run: created your settings file ..."
    -> Expected once. Fill in config\config.txt and run again.

"config.txt still has the template's placeholder value for: ..."
    -> Replace the PUT-YOUR-... / C:\Path\To\... values named in the message.

"No application folders with jars found"
    -> List the lib folders in APP_FOLDERS in config\config.txt, or put
       the jars in a folder INSIDE apps\ (apps\MyApp\*.jar) - not in apps\
       itself, and not in a folder whose name starts with _.

"<name>: NOT SCANNED - folder not found: ..." / "... no .jar files ..."
    -> A folder listed in APP_FOLDERS or app_list.txt does not exist (any
       more), or holds no jars. Fix the path in config\config.txt.

"WARNING: ... is set more than once in config.txt"
    -> The same setting appears twice; only the last one counts. Delete the
       one you don't want (APP_FOLDERS is the exception - its lines add up).

"a scheduled task named '...' already runs another copy of the tool"
    -> Two copies of the tool use the same SCHEDULE_TASK_NAME. Give this
       copy its own name in config\config.txt and run setup_schedule.bat.

setup_schedule.bat: "ERROR: Access is denied."
    -> SCHEDULE_RUN_AS_SYSTEM=yes needs an administrator: right-click
       setup_schedule.bat > Run as administrator.

The scheduled task did not run
    -> Look at reports\_logs\scheduled_runs.log, and in Task Scheduler
       (taskschd.msc) at the task's History and Last Run Result. Without
       SCHEDULE_RUN_AS_SYSTEM=yes it only runs while you are logged on.

"dependency-check.bat not found in: ..."
    -> DEPCHECK_BIN_FOLDER in config\config.txt must be the folder that
       contains dependency-check.bat. On a new machine or a fresh clone,
       run scripts\setup_dependency_check.bat first.

setup_dependency_check.bat: "the download failed"
    -> No route to GitHub. Behind a proxy, set HTTPS_PROXY first; or
       download the zip it names in a browser and run it with --zip "<zip>".

setup_dependency_check.bat: "... its SHA-256 differs"
    -> The file is not the exact 12.2.2 release (incomplete download, or
       something on the network changed it). It is not installed. Run again;
       for another version, install it yourself and set DEPCHECK_BIN_FOLDER.

"dependency-check exited with code 14 but wrote complete reports"
    -> Not a failure: one of dependency-check's analyzers reported a
       problem (the message is printed below that line) but the scan
       finished and the reports are complete.

"dependency-check.bat exited with code ..." followed by FAILED
    -> dependency-check itself failed; its own messages are above. The raw
       output is kept in work\scan_output\ for a look.

"Two settings files found"
    -> There is a config.txt next to run_dependency_check.bat AND one in
       config\. Keep your real one in config\ and delete the other.

"missing required Python package(s)" / "No module named ..."
    -> Python version only: double-click scripts\setup_venv.bat.
       If the folder was moved or copied: scripts\setup_venv.bat --recreate

"... is not saved as UTF-8"
    -> Open the named file in Notepad, File > Save As, Encoding: UTF-8.

Comments column says "AI lookup failed: ..."
    -> Usually a wrong/expired OPENAI_API_KEY or no network. It is retried
       automatically next run. Try AI_USE_WEB_SEARCH=no as a quick check.

"email delivery failed (... CERTIFICATE_VERIFY_FAILED ...)"
    -> SMTP_SERVER must be the name on the mail server's certificate; if the
       certificate is from a private CA, set SMTP_CA_BUNDLE to its .pem file.
