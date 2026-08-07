import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.given;

import java.util.Random;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class FuzzerTest {

    private final Random random = new Random();
    @Mock
    private FuzzedDataProvider data;

    @BeforeEach
    public void setUp() {
        given(data.consumeBytes(anyInt())).willAnswer(invocation -> {
            final int maxLength = invocation.getArgument(0);
            final var bytes = new byte[maxLength];
            random.nextBytes(bytes);
            return bytes;
        });
    }

    @Test
    public final void decrypt() {
        // given

        // when
        TokenDecryptFuzzer.fuzzerTestOneInput(data);

        // then (no exception)
    }

    @Test
    public final void encryptDecrypt() {
        // given

        // when
        TokenEncryptDecryptFuzzer.fuzzerTestOneInput(data);

        // then (no exception)
    }

    @Test
    public final void replay() {
        // given

        // when
        TokenReplayFuzzer.fuzzerTestOneInput(data);

        // then (no exception)
    }

    @Test
    public final void pad() {
        // given

        // when
        PayloadPaddingFuzzer.fuzzerTestOneInput(data);

        // then (no exception)
    }

}
