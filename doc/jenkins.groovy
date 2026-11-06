pipeline {
    agent { label 'x86_64' }

    parameters {
        string(defaultValue: 'master', name: 'BRANCH')
        string(defaultValue: '2026.7', name: 'VERSION')
        string(defaultValue: 'jenkins-maple', name: 'CREDENTIALS_ID')
        string(defaultValue: 'ssh://git.maple.maceroc.com/git/millegrilles.messages.python', name: 'GIT_URL')
        string(defaultValue: 'nexus.maple.maceroc.com/millegrilles/messages_python', name: 'DOCKER_IMAGE')
    }

    environment {
        NOM_APP="millegrilles_messages"
        VBUILD="${VERSION}.${BUILD_NUMBER}"
        DOCKER_IMAGE="${params.DOCKER_IMAGE}"
    }

    stages {
        stage('package build') {
            steps {
                checkout scmGit(branches: [[name: params.BRANCH]], extensions: [submodule(recursiveSubmodules: true, reference: '')], userRemoteConfigs: [[credentialsId: params.CREDENTIALS_ID, url: params.GIT_URL]])

                sh '''
                rm -r dist/ || true
                sed -i "/\\\\_VERSION__ =/c\\\\__VERSION__ = \\"${VBUILD}\\"" setup.py
                python3 setup.py sdist
                python3 setup.py bdist_wheel
                '''

                archiveArtifacts artifacts: 'dist/millegrilles_messages-*', followSymlinks: false

                sh '''
                rsync dist/millegrilles_messages-* ${PUBLISH_RSYNC_PYTHON_DEST}/dist/millegrilles-messages
                '''
            }
        }

        stage('docker build x86_64') {
            steps {
                checkout scmGit(branches: [[name: params.BRANCH]], extensions: [submodule(recursiveSubmodules: true, reference: '')], userRemoteConfigs: [[credentialsId: params.CREDENTIALS_ID, url: params.GIT_URL]])

                sh '''
                # Creer image docker
                docker build \
                  --build-arg PIP_INDEX_URL="$PIP_INDEX_URL" \
                  -t ${DOCKER_IMAGE}:${VBUILD} --build-arg VBUILD=${VBUILD} .
                '''

                withCredentials([usernamePassword(
                    credentialsId: 'nexus-jenkins',
                    usernameVariable: 'NEXUS_USER',
                    passwordVariable: 'NEXUS_PASS'
                )]) {
                    sh '''
                        echo "$NEXUS_PASS" | docker login $DOCKER_REGISTRY_URL -u $NEXUS_USER --password-stdin
                        docker push ${DOCKER_IMAGE}:${VBUILD}
                    '''
                }
            }

        }
    }
}
