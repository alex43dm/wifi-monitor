#include <stdlib.h>
#include <gtest/gtest.h>

extern "C" {
#include "../src/daemon.c"
#include "../src/server.c"
}


class Test : public testing::Test
{
public:
    Test(){}
    void TearDown(){}
};

TEST_F(Test, decode)
{
    EXPECT_EQ(START_WIFI, decode("START_WIFI", 10));
    EXPECT_EQ(STOP_WIFI, decode("STOP_WIFI", 9));
    EXPECT_EQ(GET_STATE, decode("GET_STATE", 9));
    EXPECT_EQ(STOP_SCAN, decode("STOP_SCAN", 9));
    EXPECT_EQ(START_SCAN, decode("START_SCAN", 10));
    EXPECT_EQ(SET_KICK_TIMEOUT, decode("SET_KICK_TIMEOUT 110", 20));
}

int main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
