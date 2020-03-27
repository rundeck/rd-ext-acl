/*
 * Copyright 2018 Rundeck, Inc. (http://rundeck.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.rundeck.client.ext.acl;

import com.dtolabs.rundeck.core.authorization.*;
import com.dtolabs.rundeck.core.authorization.providers.EnvironmentalContext;
import com.dtolabs.rundeck.core.authorization.providers.Policies;
import com.dtolabs.rundeck.core.authorization.providers.YamlProvider;
import com.lexicalscope.jewel.cli.CommandLineInterface;
import com.lexicalscope.jewel.cli.Option;
import lombok.Getter;
import lombok.Setter;
import org.rundeck.client.tool.InputError;
import org.rundeck.client.tool.extension.RdCommandExtension;
import org.rundeck.client.tool.extension.RdTool;
import org.rundeck.core.auth.AuthConstants;
import org.rundeck.core.auth.AuthResources;
import org.rundeck.toolbelt.Command;
import org.rundeck.toolbelt.SubCommand;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import javax.security.auth.Subject;
import java.io.*;
import java.net.URI;
import java.security.Principal;
import java.util.*;
import java.util.regex.Pattern;

@Command()
@SubCommand(path = {"acl"}, descriptions = {"Generate, Test, and Validate ACLPolicy files"})
public class Acl
        implements RdCommandExtension
{

    @Getter @Setter private RdTool rdTool;

    @CommandLineInterface
    interface AclOptions {
        @Option(shortName = "f", description = "File path. Load the specified aclpolicy file.")
        File getFile();

        boolean isFile();

        @Option(shortName = "d", description = "Directory. Load all policy files in the specified directory.")
        File getDir();

        boolean isDir();

        @Option
        File getConfigDir();

        boolean isConfigDir();

        @Option(shortName = "g", description = "Subject Groups names to validate (test command) or for by: " +
                                               "clause (create command). Accepts multiple values.")
        List<String> getGroups();

        boolean isGroups();

        @Option(shortName = "p", description = "Name of project, used in project context or for application resource.")
        String getProject();

        boolean isProject();

        @Option(shortName = "P",
                longName = "projectacl",
                description = "Project name for ACL policy access, used in application context.")
        String getProjectAcl();

        boolean isProjectAcl();

        @Option(shortName = "s", longName = "storage", description = "Storage path/name. (application context)")
        String getAppStorage();

        boolean isAppStorage();

        @Option(shortName = "j", description = "Job group/name. (project context)")
        String getJob();

        boolean isJob();

        @Option(shortName = "i", longName = "jobUuid", description = "Job uuid. (project context)")
        String getJobUUID();

        boolean isJobUUID();

        @Option(shortName = "n", description = "Node name. (project context)")
        String getNode();

        boolean isNode();

        @Option(shortName = "t", description = "Node tags. If specified, the resource match will be defined using " +
                                               "'contains'. (project context). Accepts multiple values.")
        List<String> getTags();

        boolean isTags();

        @Option(shortName = "u", description = "Subject User names to validate (test command) or for by: " +
                                               "clause (create command).")
        String getUser();

        boolean isUser();

        @Option(shortName = "v", description = "Verbose output.")
        boolean isVerbose();
    }

    @CommandLineInterface
    interface AclCreateOptions
            extends AclOptions
    {
        @Option(shortName = "i",
                longName = "stdin",
                description = "Read file or stdin for audit log data. (create command)")
        boolean isStdin();

        @Option(shortName = "c", description = "Context: either 'project' or 'application'.")
        Context getContext();

        boolean isContext();

        @Option(shortName = "R", longName = "resource", description = "Resource type name.")
        String getResource();

        boolean isResource();

        @Option(shortName = "A", longName = "adhoc", description = "Adhoc execution (project context)")
        boolean getProjectAdhoc();

        @Option(shortName = "G", longName = "generic", description = "Generic resource kind.")
        String getGenericType();

        boolean isGenericType();

        @Option(shortName = "b",
                longName = "attrs",
                description = "Attributes for the resource. A sequence of key=value pairs, multiple pairs " +
                              "can follow with a space. Use a value of '?' to see suggestions.")
        List<String> getAttributes();

        boolean isAttributes();

        @Option(shortName = "a",
                longName = "allow",
                description = "Actions to test are allowed (test command) or to allow (create command). Accepts "
                              + "multiple values.")
        List<String> getAllowAction();

        boolean isAllowAction();

        @Option(shortName = "D",
                longName = "deny",
                description = "Actions to test are denied (test command) or to deny (create command). Accepts "
                              + "multiple values.")
        List<String> getDenyAction();

        boolean isDenyAction();

        @Option(shortName = "r", description = "Match the resource using regular expressions. (create command).")
        boolean getRegex();
    }

    static enum Context {
        project,
        application
    }

    static AclSubject createSubject(Subject subject) {
        Set<Username> userPrincipals = subject.getPrincipals(Username.class);
        final String username;
        if (userPrincipals.size() > 0) {
            Username usernamep = userPrincipals.iterator().next();
            username = usernamep.getName();
        } else {
            username = null;
        }
        Set<Group> groupPrincipals = subject.getPrincipals(Group.class);
        final Set<String> groupNames = new HashSet<>();
        if (groupPrincipals.size() > 0) {
            for (Group groupPrincipal : groupPrincipals) {
                groupNames.add(groupPrincipal.getName());
            }
        }
        return new AclSubject() {
            @Override
            public String getUsername() {
                return username;
            }

            @Override
            public Set<String> getGroups() {
                return groupNames;
            }
        };
    }

    static class Username
            implements Principal
    {
        String name;

        public Username(final String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    static class Group
            implements Principal
    {
        String name;

        public Group(final String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    @Command(description = "List ACL Policies")
    public void list(AclOptions opts) throws InputError {

        final RuleEvaluator authorization = createAuthorization(opts);
        Subject subject = createSubject(opts);
        String subjdesc = opts.isGroups() ? "group " + opts.getGroups() : "username " + opts.getUser();

        info("# Application Context access for " + subjdesc + "\n");
        //iterate app context resources, test actions
        if (opts.isProject()) {
            HashMap<String, Object> res = new HashMap<>();
            res.put("name", opts.getProject());
            Map<String, Object> resourceMap = AuthorizationUtil.resourceRule(AuthConstants.TYPE_PROJECT, res);

            logDecisions(
                    "project named \"" + opts.getProject() + "\"",
                    authorization,
                    subject,
                    resources(resourceMap),
                    new HashSet<>(AuthResources.appProjectActions),
                    createAppEnv(),
                    opts
            );
        } else {
            info("\n(No project (-p) specified, skipping Application context actions for a specific project.)"
                        + "\n");
        }
        if (null != opts.getProjectAcl()) {
            HashMap<String, Object> res = new HashMap<>();
            res.put("name", opts.getProjectAcl());
            Map<String, Object> resourceMap = AuthorizationUtil.resourceRule(AuthConstants.TYPE_PROJECT_ACL, res);

            logDecisions(
                    "project_acl for Project named \"" + opts.getProjectAcl() + "\"",
                    authorization,
                    subject,
                    resources(resourceMap),
                    new HashSet<>(AuthResources.appProjectAclActions),
                    createAppEnv(),
                    opts
            );
        } else {
            info(
                    "\n(No project_acl (-P) specified, skipping Application context actions for a ACLs for a specific"
                    + " project.)\n");
        }
        if (null != opts.getAppStorage()) {
            Map<String, Object> resourceMap = createStorageResource(opts);
            logDecisions(
                    "storage path \"" + opts.getAppStorage() + "\"",
                    authorization,
                    subject,
                    resources(resourceMap),
                    new HashSet<>(AuthResources.appStorageActions),
                    createAppEnv(),
                    opts
            );
        } else {
            info(
                    "\n(No storage path (-s) specified, skipping Application context actions for a specific storage " +
                    "path.)\n"
            );
        }
        for (String kind : AuthResources.appKindActionsByType.keySet()) {
            logDecisions(
                    kind,
                    authorization,
                    subject,
                    resources(AuthorizationUtil.resourceTypeRule(kind)),
                    new HashSet<>(AuthResources.appKindActionsByType.get(kind)),
                    createAppEnv(),
                    opts
            );
        }


        if (null == opts.getProject()) {
            info("\n(No project (-p) specified, skipping Project context listing.)");
            return;
        }
        Set<Attribute> projectEnv = createAuthEnvironment(opts.getProject());

        info("\n# Project \"" + opts.getProject() + "\" access for " + subjdesc + "\n");
        //adhoc
        logDecisions(
                "Adhoc executions",
                authorization,
                subject,
                resources(createProjectAdhocResource()),
                new HashSet<>(AuthResources.projectAdhocActions),
                projectEnv,
                opts
        );
        //job
        if (null != opts.getJob()) {

            Map<String, Object> resourceMap = createProjectJobResource(opts);
            logDecisions(
                    "Job \"" + opts.getJob() + "\"",
                    authorization,
                    subject,
                    resources(resourceMap),
                    new HashSet<>(AuthResources.projectJobActions),
                    projectEnv,
                    opts
            );
        } else if (null != opts.getJobUUID()) {
            Map<String, Object> resourceMap = createProjectJobUUIDResource(opts);
            logDecisions(
                    "Job UUID\"" + opts.getJobUUID() + "\"",
                    authorization,
                    subject,
                    resources(resourceMap),
                    new HashSet<>(AuthResources.projectJobActions),
                    projectEnv,
                    opts
            );
        } else {
            info(
                    "\n(No job name(-j) or uuid (-I) specified, skipping Project context actions for a specific job.)"
                    + "\n");
        }
        //node

        if (null != opts.getNode() || null != opts.getTags()) {
            Map<String, Object> resourceMap = createProjectNodeResource(opts);
            logDecisions(
                    "Node " + (null != opts.getNode() ? ("\"" + opts.getNode() + "\"") : "") +
                    (null != opts.getTags() ? " tags: " + opts.getTags() : "")
                    ,
                    authorization,
                    subject,
                    resources(resourceMap),
                    new HashSet<>(AuthResources.projectNodeActions),
                    projectEnv,
                    opts
            );
        } else {
            info(
                    "\n(No node (-n) or tags (-t) specified, skipping Project context actions for a specific node or" +
                    " node tags.)\n");
        }

        //kinds

        for (String kind : AuthResources.projKindActionsByType.keySet()) {
            logDecisions(
                    kind,
                    authorization,
                    subject,
                    resources(AuthorizationUtil.resourceTypeRule(kind)),
                    new HashSet<>(AuthResources.projKindActionsByType.get(kind)),
                    projectEnv,
                    opts
            );
        }

    }

    private RuleEvaluator createAuthorization(final AclOptions opts) throws InputError {
        return RuleEvaluator.createRuleEvaluator(createPolicies(opts), Acl::createSubject);
    }

    /**
     * If argValidate is specified, validate the input, exit 2 if invalid. Print validation report if
     * opts.isverbose(opts,)
     *
     * @return true if validation check failed
     * @throws InputError
     */
    private boolean applyArgValidate(TestOptions opts) throws InputError {
        if (opts.isValidate()) {
            Validation validation = validatePolicies(opts);
            if (opts.isVerbose() && !validation.isValid()) {
                reportValidation(validation);
            }
            if (!validation.isValid()) {
                log("The validation " + (validation.isValid() ? "passed" : "failed"));
                return false;
            }
        }
        return true;
    }

    interface TestOptions
            extends AclCreateOptions
    {
        @Option(shortName = "V", description = "Validate all input files.")
        boolean isValidate();
    }

    @Command(description = "Test ACL Policies")
    public boolean test(TestOptions opts) throws InputError {
        if (!applyArgValidate(opts)) {
            return false;
        }
        final RuleEvaluator authorization = createAuthorization(opts);
        AuthRequest authRequest = createAuthRequestFromArgs(opts);
        HashSet<Map<String, String>> resource = resources(authRequest.resourceMap);

        boolean expectAuthorized = true;
        boolean expectDenied = false;
        Set<Decision> testResult = null;
        if (null != authRequest.actions && authRequest.actions.size() > 0) {
            testResult =
                    authorization.evaluate(
                            resource,
                            authRequest.subject,
                            authRequest.actions,
                            authRequest.environment
                    );
        } else if (null != authRequest.denyActions && authRequest.denyActions.size() > 0) {
            expectAuthorized = false;
            expectDenied = true;
            testResult = authorization.evaluate(
                    resource,
                    authRequest.subject,
                    authRequest.denyActions,
                    authRequest.environment
            );
        } else {
            throw new InputError(optionDisplayString("ALLOW") + " or " + optionDisplayString("DENY") + " is required");

        }
        boolean testPassed = true;
        boolean wasAllowed = true;
        boolean wasDenied = false;

        for (Decision decision : testResult) {
            if (!decision.isAuthorized()) {
                wasAllowed = false;
            }
            if (expectAuthorized && !decision.isAuthorized() ||
                expectDenied && decision.isAuthorized()) {
                log("Result: " + decision.explain().getCode());
                verbose(opts, decision.toString());
                switch (decision.explain().getCode()) {
                    case REJECTED_NO_SUBJECT_OR_ENV_FOUND:
                        log(
                                "Meaning: " +
                                "No rules were found among the aclpolicies that match" +
                                " the subject (user,group) and context (" +
                                (authRequest.isAppContext() ? "application" : "project") +
                                ")" +
                                " and resource (" + authRequest.resourceMap + ")"
                        );
                        break;
                    case REJECTED_DENIED:
                        log(
                                "Meaning: " +
                                "A matching rule declared that the requested action be DENIED."
                        );
                        wasDenied = true;
                }
                testPassed = false;
            } else {
                switch (decision.explain().getCode()) {
                    case REJECTED_DENIED:
                        wasDenied = true;
                }
                if (opts.isVerbose()) {
                    log(decision.toString());
                }
            }
        }
        log("The decision was: " + (wasAllowed ? "allowed" : wasDenied ? "denied" : "not allowed"));
        if (opts.isVerbose() && !testPassed) {
            log("Policies to allow the requested actions:");
            generateYaml(authRequest, System.out);
        } else if (opts.isVerbose() && !testPassed && expectAuthorized && wasDenied) {
            log(
                    "No new policy can allow the requested action.\n" +
                    "DENY rules will always prevent access, even if ALLOW " +
                    "rules also match. \n" +
                    "To allow it, you must remove the DENY rule."
            );
        }
        log("The test " + (testPassed ? "passed" : "failed"));
        return testPassed;
    }

    @Command(description = "Create ACL Policies")
    public void create(AclCreateOptions opts) throws InputError, IOException {
        List<AuthRequest> reqs = new ArrayList<>();
        if (opts.isFile() || opts.isStdin()) {
            reqs = readRequests(opts);
        } else {
            reqs.add(createAuthRequestFromArgs(opts));
        }
        //generate yaml
        for (AuthRequest req : reqs) {
            generateYaml(req, System.out);
        }
    }

    @Command(description = "Validate ACL Policies")
    public boolean validate(AclOptions opts) throws InputError, IOException {
        if (null == opts.getFile() && null == opts.getDir() && null != opts.getConfigDir()) {
            log("Using configured Rundeck etc dir: " + opts.getConfigDir());
        }
        final Validation validation = validatePolicies(opts);
        reportValidation(validation);
        log("The validation " + (validation.isValid() ? "passed" : "failed"));
        return validation.isValid();
    }

    private HashSet<Map<String, String>> resources(final Map<String, Object>... resourceMap) {
        HashSet<Map<String, String>> resource = new HashSet<>();
        for (Map<String, Object> stringObjectMap : resourceMap) {
            resource.add(toStringMap(stringObjectMap));
        }
        return resource;
    }

    private void logDecisions(
            final String title,
            final RuleEvaluator authorization,
            final Subject subject,
            final HashSet<Map<String, String>> resource,
            final HashSet<String> actions,
            final Set<Attribute> env,
            final AclOptions opts
    )
    {
        Set<Decision> evaluate = authorization.evaluate(
                resource,
                subject,
                actions,
                env
        );
        for (Decision decision : sortByAction(evaluate)) {
            log(
                    (
                            decision.isAuthorized()
                            ? "+"
                            : decision.explain().getCode() == Explanation.Code.REJECTED_DENIED ? "!" : "-"
                    ) +
                    " " +
                    decision.getAction() +
                    ": " +
                    title +
                    (decision.isAuthorized() ? "" : (" [" + decision.explain().getCode() + "]"))
            );
            if (!decision.isAuthorized() && decision.explain().getCode() == Explanation.Code.REJECTED_DENIED) {
                verbose(
                        opts,
                        "  " + decision.explain().toString()
                );
            }
        }
    }

    private void verbose(AclOptions opts, final String s) {
        if (opts.isVerbose()) {
            info(s);
        }
    }

    private void info(final String s) {
        getRdTool().getRdApp().getOutput().info(s);
    }

    private void log(final String s) {
        getRdTool().getRdApp().getOutput().output(s);
    }

    private void warn(final String s) {
        getRdTool().getRdApp().getOutput().warning(s);
    }

    private static Comparator<Decision> comparator = Comparator.comparing(Decision::getAction);

    private Set<Decision> sortByAction(final Set<Decision> evaluate) {
        TreeSet<Decision> sorted = new TreeSet<>(comparator);
        sorted.addAll(evaluate);
        return sorted;
    }



    String optionDisplayString(String value) {
        return "--" + value.toLowerCase();
    }

    private AuthRequest createAuthRequestFromArgs(AclCreateOptions opts)
            throws InputError
    {
        //determine context
        if (null == opts.getContext()) {
            throw new InputError(
                    optionDisplayString("CONTEXT") + " is required. " +
                    "Choose one of: \n" +
                    "  -c " + Context.application + "\n" +
                    "    Access to projects, users, storage, system info, execution management.\n" +
                    "  -c " + Context.project + "\n" +
                    "    Access to jobs, nodes, events, within a project."
            );
        }
        if (opts.getContext() == Context.project && !opts.isProject()) {
            throw new InputError(
                    "--project is required. Choose the name of a project, or .*: \n  -p myproject\n  -p '.*'"
            );
        }
        boolean appContext = opts.getContext() == Context.application;
        Set<Attribute> environment = appContext ? createAppEnv() : createAuthEnvironment(opts.getProject());

        //determine subject

        Subject subject = createSubject(opts);

        //determine resource
        Map<String, Object> resourceMap = new HashMap<>();

        if (opts.getContext() == Context.application && opts.getResource() != null) {
            if (!AuthResources.appTypes.contains(opts.getResource().toLowerCase())) {

                throw new InputError(
                        "--resource invalid resource type: " + opts.getResource() +
                        "  resource types in application context: " +
                        "    " + String.join("\n    ", AuthResources.appTypes)

                );
            }
            resourceMap = AuthorizationUtil.resourceRule(opts.getResource().toLowerCase(), null);
        } else if (opts.getContext() == Context.project && opts.getResource() != null) {
            if (!AuthResources.projectTypes.contains(opts.getResource().toLowerCase())) {

                throw new InputError(
                        "--resource invalid resource type: " + opts.getResource() +
                        "  resource types in project context: " +
                        "    " + String.join("\n    ", AuthResources.projectTypes)

                );
            }
            resourceMap = AuthorizationUtil.resourceRule(opts.getResource().toLowerCase(), null);
        } else if (opts.getContext() == Context.application && opts.getProject() != null) {
            HashMap<String, Object> res = new HashMap<>();
            res.put("name", opts.getProject());
            resourceMap = AuthorizationUtil.resourceRule(AuthConstants.TYPE_PROJECT, res);
        } else if (opts.getContext() == Context.application && opts.getProjectAcl() != null) {
            HashMap<String, Object> res = new HashMap<>();
            res.put("name", opts.getProjectAcl());
            resourceMap = AuthorizationUtil.resourceRule(AuthConstants.TYPE_PROJECT_ACL, res);
        } else if (opts.getContext() == Context.application && opts.getAppStorage() != null) {
            resourceMap = createStorageResource(opts);
        } else if (opts.getContext() == Context.project && opts.getJob() != null) {
            resourceMap = createProjectJobResource(opts);
        } else if (opts.getContext() == Context.project && opts.getJobUUID() != null) {
            resourceMap = createProjectJobUUIDResource(opts);
        } else if (opts.getContext() == Context.project && (opts.getNode() != null || opts.getTags() != null)) {
            resourceMap = createProjectNodeResource(opts);
        } else if (opts.getContext() == Context.project && opts.getProjectAdhoc()) {
            resourceMap = createProjectAdhocResource();
        } else if (opts.getContext() == Context.project && null != opts.getGenericType()) {
            if (!AuthResources.projectKinds.contains(opts.getGenericType().toLowerCase())) {
                throw new InputError(
                        "--generic invalid generic kind: " + opts.getGenericType() +
                        "  generic kinds in this context: " +
                        "    " + String.join("\n    ", AuthResources.projectKinds)

                );
            }
            resourceMap = AuthorizationUtil.resourceTypeRule(opts.getGenericType().toLowerCase());
        } else if (opts.getContext() == Context.application && null != opts.getGenericType()) {
            if (!AuthResources.appKinds.contains(opts.getGenericType().toLowerCase())) {

                throw new InputError(
                        "--generic invalid generic kind: " + opts.getGenericType() +
                        "  generic kind in this context: " +
                        "    " + String.join("\n    ", AuthResources.appKinds)

                );
            }
            resourceMap = AuthorizationUtil.resourceTypeRule(opts.getGenericType().toLowerCase());
        } else if (opts.getContext() == Context.project) {

            throw new InputError(
                    "Project-context resource option is required." +
                    "Possible options:\n" +
                    "  Job: " +
                    optionDisplayString("JOB") +
                    "\n" +
                    "    View, modify, create*, delete*, run, and kill specific jobs,\n" +
                    "    and toggle whether schedule and/or execution are enabled.\n" +
                    "    * Create and delete also require additional " +
                    optionDisplayString("GENERIC") +
                    " level access.\n" +
                    "  Adhoc: " +
                    optionDisplayString("ADHOC") +
                    "\n" +
                    "    View, run, and kill adhoc commands.\n" +
                    "  Node: " +
                    optionDisplayString("NODE") +
                    "\n" +
                    "      : " +
                    optionDisplayString("TAGS") +
                    "\n" +
                    "    View and run on specific nodes by name or tag.\n" +
                    "  Resource: " +
                    optionDisplayString("RESOURCE") +
                    "\n" +
                    "    Specify the resource type directly. " +
                    optionDisplayString("ATTRS") +
                    " should also be used.\n" +
                    "    resource types in this context: \n" +
                    "    " +
                    String.join("\n    ", AuthResources.projectTypes) +
                    "\n" +
                    "  Generic: " +
                    optionDisplayString("GENERIC") +
                    "\n" +
                    "    Create and delete jobs.\n" +
                    "    View and manage nodes.\n" +
                    "    View events.\n" +
                    "    generic kinds in this context: \n" +
                    "    " +
                    String.join("\n    ", AuthResources.projectKinds)

            );
        } else {

            throw new InputError(
                    "Application-context resource option is required." +
                    "Possible options:\n" +
                    "  Project: " +
                    optionDisplayString("PROJECT") +
                    "\n" +
                    "    Visibility, import, export, config, and delete executions.\n" +
                    "    *Note: Project create requires additional " +
                    optionDisplayString("GENERIC") +
                    " level access.\n" +
                    "  Project ACLs: " +
                    optionDisplayString("PROJECT_ACL") +
                    "\n" +
                    "    CRUD access for the project ACLs.\n" +
                    "  Storage: " +
                    optionDisplayString("STORAGE") +
                    "\n" +
                    "    CRUD access for the key storage system.\n" +
                    "  Resource: " +
                    optionDisplayString("RESOURCE") +
                    "\n" +
                    "    Specify the resource type directly. " +
                    optionDisplayString("ATTRS") +
                    " should also be used.\n" +
                    "    resource types in this context: \n" +
                    "    " +
                    String.join("\n    ", AuthResources.appTypes) +
                    "\n" +
                    "  Generic: " +
                    optionDisplayString("GENERIC") +
                    "\n" +
                    "    Create projects, read system info, manage system ACLs, manage users, change\n" +
                    "      execution mode, manage plugins.\n" +
                    "    generic kinds" +
                    " in this context: \n" +
                    "    " +
                    String.join("\n    ", AuthResources.appKinds)
            );
        }
        Map<String, String> attrsMap = new HashMap<>();
        boolean attrsHelp = false;
        if (opts.isAttributes()) {
            attrsHelp = parseAttrsMap(opts, attrsMap);
        }
        if (!attrsHelp && null != attrsMap && attrsMap.size() > 0) {
            resourceMap.putAll(attrsMap);
        } else if (attrsHelp && null != opts.getResource()
                   && !opts.getResource().equalsIgnoreCase(AuthConstants.TYPE_ADHOC)) {
            List<String> possibleAttrs =
                    (opts.getContext() == Context.application ? AuthResources.appResAttrsByType : AuthResources.projResAttrsByType)
                            .get(opts.getResource().toLowerCase());
            throw new InputError(
                    optionDisplayString("ATTRS") +
                    " should be specified when " +
                    optionDisplayString("RESOURCE") +
                    " is used. " +
                    "Possible attributes for resource type " + opts.getResource() + " in this context:\n" +
                    "  " + String.join("\n  ", possibleAttrs)
            );
        }

        List<String> possibleActions = new ArrayList<>(Arrays.asList("*"));

        if (opts.getContext() == Context.application && null != opts.getResource()) {
            //actions for resources for application context
            possibleActions.addAll(AuthResources.appResActionsByType.get(opts.getResource()));
        } else if (opts.getContext() == Context.project && null != opts.getResource()) {
            //actions for resources for project context
            possibleActions.addAll(AuthResources.projResActionsByType.get(opts.getResource()));
        } else if (opts.getContext() == Context.application && opts.getAppStorage() != null) {
            //actions for job
            possibleActions.addAll(AuthResources.appStorageActions);
        } else if (opts.getContext() == Context.application && opts.getProject() != null) {
            //actions for job
            possibleActions.addAll(AuthResources.appProjectActions);
        } else if (opts.getContext() == Context.application && opts.getProjectAcl() != null) {
            //actions for project_acl
            possibleActions.addAll(AuthResources.appProjectAclActions);
        } else if (opts.getContext() == Context.application && opts.getGenericType() != null) {
            //actions for job
            possibleActions.addAll(AuthResources.appKindActionsByType.get(opts.getGenericType().toLowerCase()));
        } else if (opts.getContext() == Context.project && opts.getGenericType() != null) {
            //actions for job
            possibleActions.addAll(AuthResources.projKindActionsByType.get(opts.getGenericType().toLowerCase()));
        } else if (opts.getContext() == Context.project && (opts.getJob() != null || opts.getJobUUID() != null)) {
            //actions for job
            possibleActions.addAll(AuthResources.projectJobActions);
        } else if (opts.getContext() == Context.project && opts.getProjectAdhoc()) {
            //actions for job
            possibleActions.addAll(AuthResources.projectAdhocActions);
        } else if (opts.getContext() == Context.project && (opts.getNode() != null || opts.getTags() != null)) {
            //actions for job
            possibleActions.addAll(AuthResources.projectNodeActions);
        }
        if (null == opts.getAllowAction() && null == opts.getDenyAction()) {
            //listing actions
            throw new InputError(
                    optionDisplayString("ALLOW") + " or " +
                    optionDisplayString("DENY") + " is required. " +
                    "Possible actions in this context: \n" +
                    "  " + String.join("\n  ", possibleActions)
            );
        }
        if (null != opts.getAllowAction()) {
            //validate actions
            List<String> invalid = new ArrayList<>();
            for (String s : opts.getAllowAction()) {
                if (!possibleActions.contains(s)) {
                    invalid.add(s);
                }
            }
            if (invalid.size() > 0) {
                throw new InputError(
                        optionDisplayString("ALLOW") + " specified invalid actions. " +
                        "These actions are not valid for the context:"
                        + "  " + String.join("\n  ", invalid) +
                        "Possible actions in this context: \n" +
                        "  " + String.join("\n  ", possibleActions)
                );
            }
        }
        if (null != opts.getDenyAction()) {
            //validate actions
            List<String> invalid = new ArrayList<>();
            for (String s : opts.getDenyAction()) {
                if (!possibleActions.contains(s)) {
                    invalid.add(s);
                }
            }
            if (invalid.size() > 0) {
                throw new InputError(
                        optionDisplayString("DENY") + " specified invalid actions. " +
                        "These actions are not valid for the context:\n"
                        + "  " + String.join("\n  ", invalid) + "\n\n" +
                        "Possible actions in this context:\n" +
                        "  " + String.join("\n  ", possibleActions)
                );
            }
        }


        AuthRequest request = new AuthRequest();
        request.resourceMap = resourceMap;
        request.subject = subject;
        if (null != opts.getAllowAction()) {
            request.actions = new HashSet<>(opts.getAllowAction());
        }
        request.environment = environment;
        if (null != opts.getDenyAction()) {
            request.denyActions = new HashSet<>(opts.getDenyAction());
        }
        request.regexMatch = opts.getRegex();
        request.containsMatch = opts.getContext() == Context.project && opts.getTags() != null;
        return request;
    }

    private boolean parseAttrsMap(final AclCreateOptions opts, final Map<String, String> attrsMap) {
        String key = null;
        boolean help = opts.getAttributes().size() < 1;
        for (String attribute : opts.getAttributes()) {
            if (attribute.indexOf("=") > 0) {
                String[] split = attribute.split("=", 2);
                if ("".equals(split[1]) || "?".equals(split[1])) {
                    help = true;
                }
                attrsMap.put(split[0], split[1]);
            } else {
                help = true;
            }
        }
        return help;
    }

    private Map<String, Object> createProjectNodeResource(AclOptions opts) {
        final Map<String, Object> resourceMap;
        HashMap<String, Object> res = new HashMap<>();
        if (null != opts.getNode()) {
            res.put("nodename", opts.getNode());
        }
        if (null != opts.getTags()) {
            res.put("tags", opts.getTags());
        }
        resourceMap = AuthorizationUtil.resourceRule(AuthConstants.TYPE_NODE, res);
        return resourceMap;
    }

    private Map<String, Object> createProjectJobResource(AclOptions opts) {
        final Map<String, Object> resourceMap;
        HashMap<String, Object> res = new HashMap<>();
        int nx = opts.getJob().lastIndexOf("/");
        if (nx >= 0) {
            res.put("group", opts.getJob().substring(0, nx));
            res.put("name", opts.getJob().substring(nx + 1));
        } else {
            res.put("group", "");
            res.put("name", opts.getJob());
        }
        resourceMap = AuthorizationUtil.resourceRule(AuthConstants.TYPE_JOB, res);
        return resourceMap;
    }

    private Map<String, Object> createProjectJobUUIDResource(AclOptions opts) {
        final Map<String, Object> resourceMap;
        HashMap<String, Object> res = new HashMap<>();
        res.put("uuid", opts.getJobUUID());
        resourceMap = AuthorizationUtil.resourceRule(AuthConstants.TYPE_JOB, res);
        return resourceMap;
    }

    private Map<String, Object> createProjectAdhocResource() {
        return AuthorizationUtil.resourceRule(AuthConstants.TYPE_ADHOC, new HashMap<String, Object>());
    }

    private Map<String, Object> createStorageResource(AclOptions opts) {
        final Map<String, Object> resourceMap;
        HashMap<String, Object> res = new HashMap<>();
        int nx = opts.getAppStorage().lastIndexOf("/");
        if (nx >= 0) {
            res.put("path", opts.getAppStorage());
            res.put("name", opts.getAppStorage().substring(nx + 1));
        } else {
            res.put("path", opts.getAppStorage());
            res.put("name", opts.getAppStorage());
        }
        resourceMap = AuthorizationUtil.resourceRule(AuthConstants.TYPE_STORAGE, res);
        return resourceMap;
    }

    private Subject createSubject(AclOptions opts) throws InputError {
        final Subject subject;
        if (opts.getGroups() != null || opts.getUser() != null) {
            Subject t = makeSubject(opts.getUser(), opts.getGroups());
            subject = t;
        } else {
            throw new InputError(
                    optionDisplayString("GROUPS") + " or " +
                    optionDisplayString("USER") + " are required. " +
                    "  -u user1,user2... \n" +
                    "  -g group1,group2... \n" +
                    "    Groups control access for a set of users, and correspond\n" +
                    "    to authorization roles."
            );
        }
        return subject;
    }

    private Subject makeSubject(final String argUser1user, final Collection<String> groupsList1) {
        Subject t = new Subject();
        String user = argUser1user != null ? argUser1user : "user";
        t.getPrincipals().add(new Username(user));
        if (null != groupsList1) {
            for (String s : groupsList1) {
                t.getPrincipals().add(new Group(s));
            }
        }
        return t;
    }

    private void reportValidation(final Validation validation) {
        for (Map.Entry<String, List<String>> entry : validation.getErrors().entrySet()) {
            String ident = entry.getKey();
            List<String> value = entry.getValue();
            warn(ident + ":");
            for (String s : value) {
                warn("\t" + s);
            }
        }
    }


    private Validation validatePolicies(AclOptions opts) throws InputError {
        final Validation validation;
        ValidationSet validationSet = new ValidationSet();
        if (null != opts.getFile()) {
            if (!opts.getFile().isFile()) {
                throw new InputError("File: " + opts.getFile() + ", does not exist or is not a file");
            }
            validation =
                    YamlProvider.validate(YamlProvider.sourceFromFile(opts.getFile(), validationSet), validationSet);
        } else if (null != opts.getDir()) {
            if (!opts.getDir().isDirectory()) {
                throw new InputError("File: " + opts.getDir() + ", does not exist or is not a directory");
            }
            validation = YamlProvider.validate(YamlProvider.asSources(opts.getDir()), validationSet);
        } else if (null != opts.getConfigDir()) {
            File directory = opts.getConfigDir();
            if (!directory.isDirectory()) {
                throw new InputError("File: " + directory + ", does not exist or is not a directory");
            }
            validation = YamlProvider.validate(YamlProvider.asSources(directory), validationSet);
        } else {
            throw new InputError("-f or -d are required");
        }
        return validation;
    }


    private List<AuthRequest> readRequests(AclCreateOptions opts) throws IOException {
        List<AuthRequest> reqs = new ArrayList<>();
        final Reader input;
        if (opts.isStdin()) {
            input = new InputStreamReader(System.in);
        } else {
            input = new FileReader(opts.getFile());
        }
        try (BufferedReader reader = new BufferedReader(input)) {

            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("Decision for:")) {
                    int i = line.indexOf("authorized: false");
                    if (i <= 0) {
                        verbose(opts, "skip line: " + line);
                        continue;
                    }
                    ParsePart res = parsePart("res", line, ", ", false);
                    if (null == res) {
                        verbose(opts, "no res< " + line);
                        continue;
                    }
                    Map<String, Object> resourceMap = res.resourceMap;
                    if (resourceMap.containsKey("tags") && resourceMap.get("tags").toString().contains(",")) {
                        //split tags
                        List<String> tags = Arrays.asList(resourceMap.get("tags").toString().split(","));
                        resourceMap.put("tags", tags);
                    }
                    line = line.substring(res.len);

                    res = parsePart("subject", line, " ", true);
                    if (null == res) {
                        verbose(opts, "no subject<: " + line);
                        continue;
                    }
                    Map<String, Object> subjMap = res.resourceMap;
                    Subject subject = createSubject(subjMap);
                    if (null == subject) {
                        verbose(opts, "parse subject< failed: " + subjMap + ": " + line);
                        continue;
                    }
                    line = line.substring(res.len);


                    res = parseString("action", line);
                    if (null == res) {
                        verbose(opts, "no action<: " + line);
                        continue;
                    }
                    String action = res.value;
                    line = line.substring(res.len);

                    res = parseString("env", line);
                    if (null == res) {
                        verbose(opts, "no env<: " + line);
                        continue;
                    }
                    String env = res.value;
                    line = line.substring(res.len);
                    if (env.lastIndexOf(":") < 0 || env.lastIndexOf(":") >= env.length()) {
                        verbose(opts, "env parse failed: " + line);
                        continue;
                    }

                    AuthRequest request = new AuthRequest();
                    boolean isAppContext = env.equals(
                            EnvironmentalContext.URI_BASE +
                            "application:rundeck"
                    ) || env.equals(
                            //backwards compatibility for old audit logs
                            "http://dtolabs.com/rundeck/auth/env/" +
                            "application:rundeck"
                    );
                    request.environment =
                            isAppContext ?
                            createAppEnv() :
                            createAuthEnvironment(env.substring(env.lastIndexOf(":") + 1));
                    request.actions = new HashSet<>(Arrays.asList(action));
                    request.resourceMap = resourceMap;
                    request.subject = subject;
                    reqs.add(request);
                } else {
                    verbose(opts, "did not see start. skip line: " + line);
                }
            }
        }
        return reqs;
    }

    private Map<String, String> toStringMap(final Map<String, Object> resourceMap) {
        Map<String, String> r = new HashMap<>();
        for (String s : resourceMap.keySet()) {
            Object value = resourceMap.get(s);
            if (s.equals("tags") && value instanceof Collection) {
                r.put(s, String.join(",", (Collection) value));
            } else {
                r.put(s, value.toString());
            }
        }
        return r;
    }

    private Subject createSubject(final Map<String, Object> subjMap) {
        String user;
        if (null == subjMap.get("Username") || !(subjMap.get("Username") instanceof String)) {
            return null;
        }
        if (null == subjMap.get("Group") || !(
                subjMap.get("Group") instanceof Collection
                || subjMap.get("Group") instanceof String
        )) {
            return null;
        }
        Object group = subjMap.get("Group");
        Collection<String> groups;
        if (group instanceof Collection) {
            groups = (Collection<String>) group;
        } else {
            groups = Arrays.asList((String) group);
        }
        return makeSubject(subjMap.get("Username").toString(), groups);
    }

    private class ParsePart {
        int len;
        Map<String, Object> resourceMap;
        String value;
    }

    private ParsePart parsePart(String name, String line, final String delimiter, final boolean allowMultiple) {
        Map<String, Object> resourceMap = new HashMap<>();
        int len = 0;
        String test = line;
        int v = test.indexOf(name + "<");
        if (v < 0 || v > test.length() - (name.length() + 1)) {
            return null;
        }
        String r1 = test.substring(v + name.length() + 1);
        int v2 = r1.indexOf(">");
        if (v2 < 0) {
            return null;
        }
        String restext = r1.substring(0, v2);
        resourceMap = parseMap(restext, delimiter, allowMultiple);
        if (null == resourceMap) {
            return null;
        }
        len = v + (name.length()) + 1 + v2 + 1;
        ParsePart parsePart = new ParsePart();
        parsePart.len = len;
        parsePart.resourceMap = resourceMap;
        return parsePart;
    }

    private ParsePart parseString(String name, String line) {
        Map<String, String> resourceMap = new HashMap<>();
        int len = 0;
        String test = line;
        int v = test.indexOf(name + "<");
        if (v < 0 || v > test.length() - (name.length() + 1)) {
            return null;
        }
        String r1 = test.substring(v + name.length() + 1);
        int v2 = r1.indexOf(">");
        if (v2 < 0) {
            return null;
        }
        String restext = r1.substring(0, v2);

        len = v + (name.length() + 1) + v2 + 1;
        ParsePart parsePart = new ParsePart();
        parsePart.value = restext;
        parsePart.len = len;
        return parsePart;
    }

    private Map<String, Object> parseMap(final String restext, final String delimiter, final boolean allowMultiple) {
        String[] split = restext.split(Pattern.quote(delimiter));
        if (split.length < 1) {
            return null;
        }
        HashMap<String, Object> result = new HashMap<>();
        for (final String aSplit : split) {
            String[] s = aSplit.split(":", 2);
            if (s.length < 2) {
                return null;
            }
            if (result.containsKey(s[0]) && allowMultiple) {
                if (result.get(s[0]) instanceof Collection) {
                    ((Collection<String>) result.get(s[0])).add(s[1]);
                } else if (result.get(s[0]) instanceof String) {
                    ArrayList<String> strings = new ArrayList<>();
                    strings.add((String) result.get(s[0]));
                    strings.add(s[1]);
                    result.put(s[0], strings);
                }
            } else {
                result.put(s[0], s[1]);
            }
        }
        return result;
    }

    private void generateYaml(final AuthRequest authRequest, final PrintStream out) {
        Map<String, ?> data = toDataMap(authRequest);
        DumperOptions dumperOptions = new DumperOptions();
        dumperOptions.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        Yaml yaml = new Yaml(dumperOptions);
        out.println("# create or append this to a .aclpolicy file");
        out.println("---");
        yaml.dump(data, new OutputStreamWriter(out));
    }

    /**
     * Create the map structure corresponding to yaml
     *
     * @param authRequest request
     * @return data map
     */
    public static Map<String, ?> toDataMap(final AuthRequest authRequest) {
        HashMap<String, Object> stringHashMap = new HashMap<>();
        //context
        Map<String, Object> ruleMap = new HashMap<>();
        if (authRequest.environment.equals(createAppEnv())) {
            //app context
            HashMap<String, String> s = new HashMap<>();
            s.put("application", "rundeck");
            stringHashMap.put("context", s);
        } else {
            String project = authRequest.environment.iterator().next().value;
            HashMap<String, String> s = new HashMap<>();
            s.put("project", project);
            stringHashMap.put("context", s);
        }

        //subject
        Set<Username> principals = authRequest.subject.getPrincipals(Username.class);
        if (principals.iterator().next().getName().equals("user")) {
            //use groups
            HashMap<String, Object> s = new HashMap<>();
            ArrayList<String> strings = new ArrayList<>();
            for (Group group : authRequest.subject.getPrincipals(Group.class)) {
                strings.add(group.getName());
            }
            s.put("group", strings.size() > 1 ? strings : strings.iterator().next());
            stringHashMap.put("by", s);
        } else {
            HashMap<String, String> s = new HashMap<>();
            s.put("username", principals.iterator().next().getName());
            stringHashMap.put("by", s);
        }

        Map<String, Object> resource = new HashMap<>();
        //resource
        String type = authRequest.resourceMap.get("type").toString();
        resource.putAll(authRequest.resourceMap);
        resource.remove("type");

        //project context type
        HashMap<String, Object> s = new HashMap<>();
        ArrayList<Map<String, Object>> maps = new ArrayList<>();
        s.put(type, maps);
        HashMap<String, Object> r = new HashMap<>();
        if (resource.size() > 0) {
            r.put(authRequest.regexMatch ? "match" : authRequest.containsMatch ? "contains" : "equals", resource);
        }
        if (authRequest.actions != null && authRequest.actions.size() > 0) {

            r.put(
                    "allow",
                    authRequest.actions.size() > 1
                    ? new ArrayList<>(authRequest.actions)
                    : authRequest.actions.iterator().next()
            );
        }
        if (authRequest.denyActions != null && authRequest.denyActions.size() > 0) {
            r.put(
                    "deny",
                    authRequest.denyActions.size() > 1
                    ? new ArrayList<>(authRequest.denyActions)
                    : authRequest.denyActions.iterator().next()
            );
        }
        maps.add(r);
        ruleMap.putAll(s);

        stringHashMap.put("for", ruleMap);
        stringHashMap.put("description", authRequest.description != null ? authRequest.description : "generated");


        return stringHashMap;
    }

    private Policies createPolicies(AclOptions options)
            throws InputError
    {
        final Policies policies;
        if (options.isFile()) {
            policies = Policies.loadFile(options.getFile());
        } else if (options.isDir()) {
            if (!options.getDir().isDirectory()) {
                throw new RuntimeException("File: " + options.getDir() + ", does not exist or is not a directory");
            }
            policies = Policies.load(options.getDir());
        } else if (options.isConfigDir()) {
            log("Using configured Rundeck etc dir: " + options.getConfigDir());
            if (!options.getConfigDir().isDirectory()) {
                throw new RuntimeException("File: "
                                           + options.getConfigDir()
                                           + ", does not exist or is not a directory");
            }
            policies = Policies.load(options.getConfigDir());
        } else {
            throw new InputError(String.format(
                    "One of %s or %s are required",
                    optionDisplayString("file"),
                    optionDisplayString("dir")
            ));
        }
        return policies;
    }

    private class AuthRequest {
        String description;
        Map<String, Object> resourceMap;
        boolean regexMatch;
        boolean containsMatch;
        Subject subject;
        Set<String> actions;
        Set<Attribute> environment;

        boolean isAppContext() {
            return environment.equals(createAppEnv());
        }

        Set<String> denyActions;
    }

    private static Set<Attribute> createAppEnv() {
        return Collections.singleton(
                new Attribute(URI.create(EnvironmentalContext.URI_BASE +
                                         "application"), "rundeck")
        );
    }

    private Set<Attribute> createAuthEnvironment(final String argProject) {
        return Collections.singleton(new Attribute(
                URI.create(EnvironmentalContext.URI_BASE + "project"),
                argProject
        ));
    }
}
