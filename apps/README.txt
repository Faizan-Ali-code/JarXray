INPUT FOLDER - used only when config\config.txt lists no application folders
(APP_FOLDERS / app_list.txt). The usual setup lists each deployed
application's lib folder there instead, and nothing has to be put here.

One subfolder per application, with that application's jars inside it:

    apps\
      OrderService\    *.jar
      BillingApi\            *.jar

Every run then scans each of these folders. Before the scan, internal jars
(INTERNAL_PACKAGES in config.txt) are moved into an internal_jars_<date>
subfolder inside the application's folder, so only third-party jars are
checked.

Folders whose name starts with _ are ignored - park sample or test data in
e.g. apps\_samples\ without it being scanned on every run.

Reports appear in ..\reports\<application>\.
