// Same stages as .github/workflows/ci.yml, for a Jenkins agent that has Docker,
// Terraform, Ansible (with community.crypto) and Python installed.
pipeline {
    agent { label 'docker' }

    options {
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    stages {
        stage('Lint') {
            steps { sh 'make lint' }
        }
        stage('Terraform apply') {
            steps { sh 'make up' }
        }
        stage('Ansible') {
            steps { sh 'make configure' }
        }
        stage('Idempotence') {
            steps { sh 'make idempotence' }
        }
        stage('Tests') {
            steps { sh 'make test' }
        }
        stage('Alert drill') {
            steps { sh 'make drill' }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '.secrets/second-run.log', allowEmptyArchive: true
            sh 'make down'
        }
    }
}
