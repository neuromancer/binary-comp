char g_Title_00407030[8] = "ALIEN!";
int g_Bonus_00407038 = 9;
int g_Threshold_0040703C = 10;
int g_Rotor_00407040[3] = {3, 5, 8};

class ScoreTable {
public:
    ScoreTable(int seed) : seed_(seed) {}
    int score(int value) const;

private:
    int seed_;
};

class Reactor {
public:
    Reactor(int heat) : heat_(heat) {}
    int tick(int coolant);

private:
    int heat_;
};

class Door {
public:
    Door(int key) : key_(key) {}
    int canOpen(int passcode) const;

private:
    int key_;
};

class LessonLog {
public:
    LessonLog(int base) : base_(base) {}
    int severity(int channel) const;

private:
    int base_;
};

/* Function start: 0x00401029 */
int ScoreTable::score(int value) const
{
    int total = value + seed_;
    if (total > 12) {
        total += g_Bonus_00407038;
    }
    return total;
}

/* Function start: 0x00401061 */
int Reactor::tick(int coolant)
{
    heat_ += 3;
    if (coolant > 0) {
        heat_ -= coolant * 3;
    }
    return heat_;
}

/* Function start: 0x0040109E */
int Door::canOpen(int passcode) const
{
    if (passcode == key_) {
        return 1;
    }
    return 0;
}

/* Function start: 0x004010E8 */
int LessonLog::severity(int channel) const
{
    int severity = base_ + channel;
    if (g_Title_00407030[0] == 'A') {
        severity += g_Rotor_00407040[channel & 1];
    }
    return severity;
}

/* Function start: 0x00401185 */
int boundary_after_reconstructed(int value)
{
    return value + 1;
}

int main()
{
    ScoreTable scores(4);
    Reactor reactor(12);
    Door door(1234);
    LessonLog log(2);

    return scores.score(9)
        + reactor.tick(3)
        + door.canOpen(7)
        + log.severity(1)
        + boundary_after_reconstructed(5);
}
