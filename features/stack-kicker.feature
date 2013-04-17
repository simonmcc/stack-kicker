Feature: Build application stacks in the cloud using Chef

    Scenario: App just runs
        When I get help for "stack-kicker"
        Then the exit status should be 0
        And the banner should be present
        And the banner should document that this app takes options
        And the following options should be documented:
          |--version|
        And the banner should document that this app's arguments are: 
          |task|which is required|

    Scenario: show-stacks shows the stacks defined in the current Stackfile
        Given a 2 stack Stackfile
        When I successfully run "stack-kicker show-stacks"
        Then both stacks are listed by show-stack

    Scenario: show-stack shows the stacks defined in the current Stackfile
        Given a 2 stack Stackfile
        When I successfully run "stack-kicker show-stack"
        Then the nodes in both stacks are listed by show-stack

    Scenario: show-stack shows the stack defined in the current Stackfile
        Given a single stack Stackfile
        When I successfully run "stack-kicker show-stack"
        Then the nodes in both stacks are listed by show-stack

