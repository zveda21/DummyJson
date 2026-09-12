pipeline {

    agent {
        label 'mac-security'
    }

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    stages {

        stage('Environment') {
            steps {
                sh '''
                    echo "=============================="
                    echo "JENKINS ENVIRONMENT"
                    echo "=============================="

                    echo "JENKINS_HOME=$JENKINS_HOME"
                    echo "WORKSPACE=$WORKSPACE"
                    echo "PWD=$(pwd)"

                    echo ""
                    echo "Java:"
                    java -version

                    echo ""
                    echo "Maven:"
                    mvn -version

                    echo ""
                    echo "Git:"
                    git --version
                '''
            }
        }

        stage('Run Security Tests') {
            steps {
                script {

                    int testExitCode = sh(
                        script: 'mvn clean test',
                        returnStatus: true
                    )

                    echo "Maven test exit code: ${testExitCode}"

                    if (testExitCode != 0) {
                        currentBuild.result = 'FAILURE'

                        error(
                            "Security test execution failed. "
                            + "TestNG/Surefire and Allure reports will still be published."
                        )
                    }
                }
            }
        }
    }

    post {

        always {

            echo 'Publishing TestNG and Allure results...'

            junit(
                testResults: 'target/surefire-reports/*.xml',
                allowEmptyResults: true
            )

            allure(
                includeProperties: false,
                results: [
                    [
                        path: 'allure-results'
                    ]
                ]
            )

            archiveArtifacts(
                artifacts: '''
                    target/surefire-reports/**/*,
                    allure-results/**/*
                ''',
                allowEmptyArchive: true
            )
        }

        success {
            echo '✅ Security test pipeline completed successfully.'
        }

        failure {
            echo '❌ Security test pipeline failed.'
        }

        cleanup {
            echo '🧹 Pipeline cleanup completed.'
        }
    }
}
