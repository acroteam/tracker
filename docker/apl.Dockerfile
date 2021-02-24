FROM centos:7

# 'centos-release-scl' repository provides GCC v.7 (devtoolset-7-gcc-c++)
# It will be available starting with next yum transaction
RUN yum install -y centos-release-scl

RUN yum install -y \
        devtoolset-7-gcc-c++ \
        make \
        rpm-build \
        rpm-devel \
        wget \
    && yum clean all

# gcc v.7 is installed into '/opt/rh/devtoolset-7/root/'
# Let's add gcc v.7 into 'PATH' to make it used by default
ENV \
    PATH=/opt/rh/devtoolset-7/root/usr/bin:$PATH \
    LD_LIBRARY_PATH=/opt/rh/devtoolset-7/root/usr/lib64
